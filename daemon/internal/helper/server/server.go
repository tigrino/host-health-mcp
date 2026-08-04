// Package server implements the helper's unix-socket listener. The
// socket lives at /run/host-health-mcp/helper.sock with mode 0660,
// owned root:<daemon-group>. The helper chowns both the socket and
// its parent runtime directory at bind time so the daemon (which
// runs as an unprivileged user) can traverse the dir and connect to
// the socket. SO_PEERCRED then verifies the connecting peer's uid
// matches the daemon's (design §6.7).
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"host-health-mcp/daemon/internal/helper/dispatch"
	"host-health-mcp/daemon/internal/shared/proto"
)

// Config configures a Server.
type Config struct {
	// SocketPath is the absolute path of the unix socket the helper
	// listens on.
	SocketPath string
	// AllowedUID is the only uid permitted to connect. SO_PEERCRED is
	// consulted on every accept.
	AllowedUID uint32
	// SocketGID is the group the socket and its parent directory are
	// chowned to after bind so the daemon can traverse and connect.
	// Zero leaves ownership as root:root (used in tests).
	SocketGID uint32
	// SocketMode is the file mode applied to the socket after bind.
	SocketMode os.FileMode
	// Registry is the dispatch table.
	Registry *dispatch.Registry
	// OpDeadline resolves the deadline to apply to one op, given the
	// caller's remaining budget in milliseconds from the request
	// frame. Nil selects fallbackOpDeadline; it must never resolve to
	// zero, since a handler running on an undeadlined context is what
	// this exists to prevent.
	OpDeadline func(op string, callerMS int) time.Duration
}

// Server accepts daemon connections on a unix socket and routes each
// request frame to the registered handler.
type Server struct {
	cfg Config
	ln  net.Listener

	mu   sync.Mutex
	open map[net.Conn]struct{}

	// sem bounds concurrent handleConn goroutines. See maxConns.
	sem chan struct{}
}

// New constructs a Server. It does not listen yet; call Serve.
func New(cfg Config) *Server {
	return &Server{
		cfg:  cfg,
		open: make(map[net.Conn]struct{}),
		sem:  make(chan struct{}, maxConns),
	}
}

// Serve binds the unix socket and runs the accept loop until ctx is
// cancelled. The socket is removed before bind if a stale file is
// present and re-removed on shutdown.
func (s *Server) Serve(ctx context.Context) error {
	// forbidden:allow — the helper's own listening socket under its
	// systemd RuntimeDirectory=; a stale file from an unclean stop
	// makes bind fail. Not a health-check code path.
	if err := os.Remove(s.cfg.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("server: stale socket remove: %w", err)
	}
	ln, err := net.Listen("unix", s.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("server: listen: %w", err)
	}
	// forbidden:allow — mode 0660 on the socket this process just
	// created, so the daemon's group can connect. Bind leaves it at
	// 0777&~umask otherwise.
	if err := os.Chmod(s.cfg.SocketPath, s.cfg.SocketMode); err != nil {
		ln.Close()
		return fmt.Errorf("server: chmod socket: %w", err)
	}
	// systemd's RuntimeDirectory= creates /run/host-health-mcp/ as
	// root:root because the helper unit runs as root:root. The
	// daemon (an unprivileged user) cannot traverse a root:root 0750
	// directory. Chown the parent and the socket itself to the
	// daemon's primary group so it can connect. Requires CAP_CHOWN
	// in the helper unit's bounding set; the shipped base unit
	// keeps CAP_CHOWN even when manifest-derived caps would
	// otherwise be empty.
	if s.cfg.SocketGID != 0 {
		parent := filepath.Dir(s.cfg.SocketPath)
		// forbidden:allow — the helper's own RuntimeDirectory=, which
		// systemd creates root:root; the unprivileged daemon cannot
		// traverse it otherwise. Group only, never mode.
		if err := os.Chown(parent, 0, int(s.cfg.SocketGID)); err != nil {
			ln.Close()
			return fmt.Errorf("server: chown runtime dir %s: %w", parent, err)
		}
		// forbidden:allow — same handoff, on the socket this process
		// just created.
		if err := os.Chown(s.cfg.SocketPath, 0, int(s.cfg.SocketGID)); err != nil {
			ln.Close()
			return fmt.Errorf("server: chown socket: %w", err)
		}
	}
	s.ln = ln

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	var backoff time.Duration
	var lastRejectLog time.Time
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				s.closeAll()
				return ctx.Err()
			}
			// A temporary accept error must not kill the helper. EMFILE
			// is the case that matters and it is self-inflicted: the fd
			// ceiling is reachable from a burst of daemon connections,
			// and returning here reaches log.Fatalf in main, so the
			// privileged half of the system exits on a condition that
			// clears by itself a moment later. Back off and retry.
			if isTemporaryAcceptErr(err) {
				backoff = nextBackoff(backoff)
				log.Printf("helper: accept: %v (retrying in %v)", err, backoff)
				select {
				case <-time.After(backoff):
					continue
				case <-ctx.Done():
					s.closeAll()
					return ctx.Err()
				}
			}
			return fmt.Errorf("server: accept: %w", err)
		}
		backoff = 0

		// Bound concurrent connections. The daemon caps its own
		// helper fan-out at 8, but daemon-side self-restraint is
		// exactly what a privilege boundary must not depend on: the
		// helper exists because the daemon is the network-facing half
		// that may be compromised. Per-connection cost here is high —
		// firewall_inspect alone can allocate 32 MiB for a ruleset
		// plus 16 MiB per set fetch, in a root process.
		//
		// Reject rather than queue. A caller that is over the limit
		// learns immediately; queueing would let a burst sit on
		// kernel-side accept queues holding fds.
		//
		// Peer check first: an unauthorised peer must not occupy one of
		// the 16 slots for the duration of its own rejection. The
		// semaphore is a privilege-boundary control, so the cheapest
		// rejection comes first.
		if !s.checkPeer(conn) {
			conn.Close()
			continue
		}
		select {
		case s.sem <- struct{}{}:
		default:
			conn.Close()
			// A dropped connection at a privilege boundary is worth a
			// line, but not one per attempt: the daemon sees only EOF
			// here, so without this the condition is invisible on both
			// sides.
			if time.Since(lastRejectLog) > time.Minute {
				log.Printf("helper: at capacity (%d connections); rejecting", maxConns)
				lastRejectLog = time.Now()
			}
			continue
		}
		s.track(conn)
		go func() {
			defer func() { <-s.sem }()
			s.handleConn(ctx, conn)
		}()
	}
}

// maxConns bounds concurrent daemon connections to the helper.
//
// The number is derived from the unit's MemoryMax=, not chosen for
// comfort, and the two must be changed together. Worst case per
// connection is firewall_inspect: firewallRulesetCap is 32 MiB of
// captured stdout plus firewallSetListCap 16 MiB per set fetch, and
// unmarshalling that JSON into Go structures costs several times the
// wire bytes again. At 16 connections that is ~768 MiB of captured
// bytes against a 1 GiB hard ceiling, with MemoryHigh= throttling
// first.
//
// An earlier revision paired 32 connections with MemoryMax=512M, which
// the arithmetic does not support by a factor of three: a host with
// the large nftables ban sets firewall_inspect is explicitly sized for
// would have had its ROOT helper OOM-killed under ordinary operator
// polling, and systemd's StartLimitBurst would then park the unit.
//
// 16 also stays above the daemon's own helper fan-out cap of 8, so the
// limit never binds on a well-behaved daemon — it exists for a
// compromised one.
const maxConns = 16

const (
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = time.Second
)

func nextBackoff(d time.Duration) time.Duration {
	if d == 0 {
		return acceptBackoffMin
	}
	if d *= 2; d > acceptBackoffMax {
		return acceptBackoffMax
	}
	return d
}

// isTemporaryAcceptErr reports whether an accept error is a
// resource-exhaustion condition that clears on its own. net.Error's
// Temporary() is deprecated and does not cover these, so the syscall
// errnos are matched directly.
//
// EINTR and ECONNABORTED are deliberately absent: internal/poll's
// accept loop already retries both before returning, so listing them
// would be coverage of paths that cannot occur. There is no
// net.Error/Timeout() case either — this is a unix listener and no
// deadline is ever set on it, so Accept cannot time out.
func isTemporaryAcceptErr(err error) bool {
	return errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.ENOMEM)
}

func (s *Server) track(c net.Conn) {
	s.mu.Lock()
	s.open[c] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.open, c)
	s.mu.Unlock()
}

func (s *Server) closeAll() {
	s.mu.Lock()
	for c := range s.open {
		c.Close()
	}
	s.open = make(map[net.Conn]struct{})
	s.mu.Unlock()
}

// idleTimeout bounds how long the helper will wait for the next
// request frame on an established connection. Defence-in-depth
// against a daemon-side fd leak or partial-write attacker holding
// open a helper goroutine indefinitely.
const idleTimeout = 60 * time.Second

func (s *Server) handleConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	defer s.untrack(c)

	for {
		_ = c.SetReadDeadline(time.Now().Add(idleTimeout))
		var req proto.Request
		if err := proto.ReadFrame(c, &req); err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Time{})

		resp := s.dispatch(ctx, &req)

		_ = c.SetWriteDeadline(time.Now().Add(idleTimeout))
		if err := proto.WriteFrameWithCap(c, resp, proto.MaxResponseFrame); err != nil {
			return
		}
		_ = c.SetWriteDeadline(time.Time{})
	}
}

func (s *Server) checkPeer(c net.Conn) bool {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var ucred *syscall.Ucred
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		ucred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || sockErr != nil || ucred == nil {
		return false
	}
	return ucred.Uid == s.cfg.AllowedUID
}

// fallbackOpDeadline applies when Config.OpDeadline is nil.
const fallbackOpDeadline = 9500 * time.Millisecond

func (s *Server) dispatch(ctx context.Context, req *proto.Request) *proto.Response {
	if !proto.IsKnownOp(req.Op) {
		return errResp(proto.CodeBadOp, "unknown op token")
	}
	h, ok := s.cfg.Registry.Lookup(req.Op)
	if !ok {
		return errResp(proto.CodeBadOp, "op not compiled into this helper")
	}

	// The single chokepoint where every op acquires a bound. The
	// process-lifetime context handed in by Serve carries no deadline,
	// so without this the exec.CommandContext cancel path — and the
	// whole SIGTERM/KillGrace/SIGKILL chain behind it — never fires.
	// A smartctl blocked on a failing SATA device (exactly the state
	// the storage tool exists to report) leaked a subprocess and a
	// goroutine per poll, forever.
	d := fallbackOpDeadline
	if s.cfg.OpDeadline != nil {
		d = s.cfg.OpDeadline(req.Op, req.DeadlineMS)
	}
	opCtx, cancel := context.WithTimeout(ctx, d)
	defer cancel()

	result, err := h(opCtx, req.Param)
	if err != nil {
		var de *dispatch.Error
		if errors.As(err, &de) {
			return errRespFromDispatch(de)
		}
		// exec.classify already maps a subprocess deadline to a typed
		// dispatch.Error, which the branch above keeps intact along
		// with its argv and stderr summary. This catches the other
		// shape: a handler that honours a context directly (a bounded
		// read, a socket dial) and returns the raw error.
		//
		// Usually that is opCtx, since the parent carries no deadline
		// of its own — but a handler with its own inner WithTimeout
		// lands here too. CodeDeadline is the right answer either way.
		// Note os.ErrDeadlineExceeded, which a net.Conn read deadline
		// produces, is a DIFFERENT sentinel and does not match here; it
		// falls through to CodeInternal below.
		if errors.Is(err, context.DeadlineExceeded) {
			return errResp(proto.CodeDeadline, "op exceeded its deadline")
		}
		return errResp(proto.CodeInternal, err.Error())
	}

	body, mErr := json.Marshal(result)
	if mErr != nil {
		return errResp(proto.CodeInternal, "result marshal: "+mErr.Error())
	}
	return &proto.Response{Status: proto.StatusOK, Data: body}
}

func errResp(code, msg string) *proto.Response {
	return &proto.Response{
		Status:  proto.StatusErr,
		Code:    code,
		Message: msg,
	}
}

func errRespFromDispatch(de *dispatch.Error) *proto.Response {
	return &proto.Response{
		Status:       proto.StatusErr,
		Code:         de.Code,
		Message:      de.Message,
		StderrBytes:  de.StderrBytes,
		StderrSHA256: de.StderrSHA256,
		StderrPrefix: de.StderrPrefix,
		ToolExit:     de.ToolExit,
		Argv:         de.Argv,
	}
}
