package ops

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
	"time"
)

// AuditStatus is the typed result for op read_audit_status. Mirrors
// the daemon's security.auditd block plus a NetlinkError soft-error
// channel: when AUDIT_GET fails for a non-absent reason (missing
// CAP_AUDIT_CONTROL, EPERM, timeout), the helper still returns a
// partial result with NetlinkError populated and the filesystem-
// derived LastRotationTS populated. The daemon surfaces NetlinkError
// in warnings[].
type AuditStatus struct {
	Present         bool       `json:"present"`
	QueueDepth      *int       `json:"queue_depth"`
	LostEvents      *int       `json:"lost_events"`
	LastRotationTS  *time.Time `json:"last_rotation_ts"`
	NetlinkError    string     `json:"netlink_error,omitempty"`
}

// ReadAuditStatus queries the kernel audit subsystem over
// NETLINK_AUDIT and additionally stats /var/log/audit/ for the
// last-rotation timestamp. The netlink call needs CAP_AUDIT_CONTROL
// (audit_netlink_ok() routes AUDIT_GET through the same gate as the
// rule-modification opcodes); the directory stat needs only
// CAP_DAC_READ_SEARCH which the helper already holds when the
// manifest enables the security tool.
//
// The two sources are independent: a failure in one no longer
// suppresses the other. If AUDIT_GET fails, queue_depth and
// lost_events stay null and the netlink failure is recorded in the
// NetlinkError field of the result (surfaced by the daemon as a
// warning); last_rotation_ts still populates from the
// /var/log/audit/ scan.
//
// Reports present=false only when the kernel was built without
// CONFIG_AUDIT (no NETLINK_AUDIT protocol at all).
func ReadAuditStatus(ctx context.Context, _ string) (any, error) {
	out := AuditStatus{}

	st, err := queryAuditStatus(ctx)
	switch {
	case errors.Is(err, errKernelAuditAbsent):
		// kernel has no audit subsystem; both netlink and rotation
		// have nothing to report. Present stays false, no warning
		// needed.
		return out, nil
	case err != nil:
		// netlink failed for a non-absent reason (caps, EPERM,
		// timeout, malformed). Record the error string; keep going
		// so rotation can still populate.
		out.NetlinkError = err.Error()
	default:
		out.Present = true
		backlog := int(st.Backlog)
		lost := int(st.Lost)
		out.QueueDepth = &backlog
		out.LostEvents = &lost
	}

	// last_rotation_ts: scan /var/log/audit/ for the newest rotated
	// file (audit.log.1, audit.log.2, ...). auditd's own ROTATE
	// action does NOT gzip by default on Debian, so the previous
	// filter that required .gz missed every rotation. Match the
	// numbered-suffix shape instead.
	if ts := newestRotatedLog("/var/log/audit", "audit.log."); !ts.IsZero() {
		out.LastRotationTS = &ts
	}

	return out, nil
}

// rotatedSuffixRE matches the numbered-suffix portion of a rotated
// log filename — `.1`, `.2`, `.1.gz`, `.2.gz`, etc. — but not the
// live `.log` file itself.
var rotatedSuffixRE = regexp.MustCompile(`^[0-9]+(\.gz)?$`)

// newestRotatedLog returns the mtime of the newest rotated file
// matching prefix in dir. Rotated files are recognised by a numeric
// suffix (optionally followed by .gz) so logrotate-managed gzipped
// rotations and auditd-managed plain rotations both qualify.
func newestRotatedLog(dir, prefix string) time.Time {
	entries, err := os.ReadDir(dir)
	if err != nil {
		// fs.ErrNotExist (no audit log dir on this host) and
		// permission errors both result in a null LastRotationTS,
		// which is the correct signal.
		return time.Time{}
	}
	var newest time.Time
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		if !rotatedSuffixRE.MatchString(strings.TrimPrefix(name, prefix)) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	if newest.IsZero() {
		return newest
	}
	return newest.UTC()
}
