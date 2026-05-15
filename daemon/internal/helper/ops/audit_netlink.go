package ops

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Netlink-direct query of the kernel audit subsystem. Replaces the
// previous `auditctl -s` subprocess so the helper doesn't depend on
// the auditctl 4.0.x userspace policy (which refuses every subcommand,
// including read-only `-s`, without CAP_AUDIT_CONTROL in the process's
// effective set; the audit_can_control() check at the top of main()
// has no euid==0 fallback).
//
// Empirically the kernel routes AUDIT_GET through
// audit_netlink_ok()'s CAP_AUDIT_CONTROL gate — same case block as
// AUDIT_SET, AUDIT_ADD_RULE, AUDIT_DEL_RULES on Debian 13's 6.12.x
// kernels. CAP_AUDIT_READ only gates audit_bind() for the multicast
// audit-event stream (used by rsyslog/auditd-plugins/laurel), not
// for AUDIT_GET. Talking to NETLINK_AUDIT directly therefore needs
// the same CAP_AUDIT_CONTROL the userspace tool would have needed;
// the win is avoiding a subprocess and honouring the kernel's actual
// access control (no userspace overlay).
//
// 1.9.0 release note had this wrong; 1.9.1 corrects both the cap
// requirement (caps-template now adds CAP_AUDIT_CONTROL for the
// security tool) and the inline narrative.

const (
	auditGet           = 1000 // AUDIT_GET nlmsg_type
	nlmsgError         = 2
	auditStatusMinSize = 32 // first eight uint32 fields of audit_status
)

// auditStatus mirrors the first eight u32s of the kernel's
// audit_status struct. Later kernels extend the tail; ignored here.
type auditStatus struct {
	Mask         uint32
	Enabled      uint32
	Failure      uint32
	Pid          uint32
	RateLimit    uint32
	BacklogLimit uint32
	Lost         uint32
	Backlog      uint32
}

// errKernelAuditAbsent signals "this kernel lacks CONFIG_AUDIT" — a
// soft no rather than a hard failure. The helper surfaces it as
// present=false instead of returning an error.
var errKernelAuditAbsent = errors.New("kernel audit subsystem not present")

// queryAuditStatus opens a NETLINK_AUDIT socket and issues AUDIT_GET.
// Returns the parsed audit_status on success. Returns
// errKernelAuditAbsent when the kernel does not implement
// NETLINK_AUDIT (CONFIG_AUDIT=n). Every other failure mode (EPERM
// from missing CAP_AUDIT_CONTROL, timeout, malformed reply) is
// returned verbatim so the caller can surface the cause.
func queryAuditStatus(ctx context.Context) (auditStatus, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_AUDIT)
	if err != nil {
		if errors.Is(err, syscall.EPROTONOSUPPORT) || errors.Is(err, syscall.EAFNOSUPPORT) {
			return auditStatus{}, errKernelAuditAbsent
		}
		return auditStatus{}, fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd)

	addr := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, addr); err != nil {
		return auditStatus{}, fmt.Errorf("netlink bind: %w", err)
	}

	// Apply ctx deadline as a socket-level timeout so blocked recv
	// is bounded even without using the runtime poller.
	if dl, ok := ctx.Deadline(); ok {
		remain := time.Until(dl)
		if remain <= 0 {
			return auditStatus{}, context.DeadlineExceeded
		}
		tv := unix.NsecToTimeval(remain.Nanoseconds())
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
	}

	// nlmsghdr (16 bytes), no payload. Request + Acknowledge.
	var req [16]byte
	binary.LittleEndian.PutUint32(req[0:4], 16)
	binary.LittleEndian.PutUint16(req[4:6], auditGet)
	binary.LittleEndian.PutUint16(req[6:8], uint16(unix.NLM_F_REQUEST|unix.NLM_F_ACK))
	binary.LittleEndian.PutUint32(req[8:12], 1)
	// nlmsg_pid stays 0 — kernel will fill in our socket's port.

	if err := unix.Sendto(fd, req[:], 0, addr); err != nil {
		return auditStatus{}, fmt.Errorf("netlink send: %w", err)
	}

	buf := make([]byte, 8192)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				return auditStatus{}, context.DeadlineExceeded
			}
			return auditStatus{}, fmt.Errorf("netlink recv: %w", err)
		}
		if n < 16 {
			return auditStatus{}, errors.New("netlink: truncated header")
		}
		msgLen := binary.LittleEndian.Uint32(buf[0:4])
		typ := binary.LittleEndian.Uint16(buf[4:6])
		if int(msgLen) > n {
			return auditStatus{}, errors.New("netlink: short message body")
		}
		switch typ {
		case nlmsgError:
			if n < 20 {
				return auditStatus{}, errors.New("netlink: truncated error")
			}
			errno := int32(binary.LittleEndian.Uint32(buf[16:20]))
			if errno == 0 {
				// Pure ack with no payload — should not happen for
				// AUDIT_GET; the kernel emits an AUDIT_GET reply
				// with the status struct. Treat as protocol error.
				return auditStatus{}, errors.New("netlink: bare ack, no AUDIT_GET reply")
			}
			return auditStatus{}, fmt.Errorf("netlink: kernel returned errno %d (%s)", -errno, syscall.Errno(-errno).Error())
		case auditGet:
			if n < 16+auditStatusMinSize {
				return auditStatus{}, errors.New("netlink: short audit_status payload")
			}
			return parseAuditStatusBytes(buf[16 : 16+auditStatusMinSize]), nil
		default:
			// Unexpected message type. Keep reading.
		}
	}
}

func parseAuditStatusBytes(b []byte) auditStatus {
	return auditStatus{
		Mask:         binary.LittleEndian.Uint32(b[0:4]),
		Enabled:      binary.LittleEndian.Uint32(b[4:8]),
		Failure:      binary.LittleEndian.Uint32(b[8:12]),
		Pid:          binary.LittleEndian.Uint32(b[12:16]),
		RateLimit:    binary.LittleEndian.Uint32(b[16:20]),
		BacklogLimit: binary.LittleEndian.Uint32(b[20:24]),
		Lost:         binary.LittleEndian.Uint32(b[24:28]),
		Backlog:      binary.LittleEndian.Uint32(b[28:32]),
	}
}
