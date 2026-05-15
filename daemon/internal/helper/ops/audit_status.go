package ops

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"time"
)

// AuditStatus is the typed result for op read_audit_status. Mirrors
// the daemon's security.auditd block.
type AuditStatus struct {
	Present         bool       `json:"present"`
	QueueDepth      *int       `json:"queue_depth"`
	LostEvents      *int       `json:"lost_events"`
	LastRotationTS  *time.Time `json:"last_rotation_ts"`
}

// ReadAuditStatus queries the kernel audit subsystem over
// NETLINK_AUDIT. Replaces the previous `auditctl -s` invocation
// (which on audit-userspace 4.0.x refuses to run without
// CAP_AUDIT_CONTROL even for read-only operations); the kernel's
// own AUDIT_GET check requires only CAP_AUDIT_READ, which the
// helper already holds when the manifest enables the security tool.
//
// Reports present=false when the kernel was built without
// CONFIG_AUDIT (no NETLINK_AUDIT protocol). Reports an error for
// every other failure mode (EPERM from missing caps, timeout,
// malformed reply) so the daemon's warnings[] surfaces the cause.
func ReadAuditStatus(ctx context.Context, _ string) (any, error) {
	out := AuditStatus{}

	st, err := queryAuditStatus(ctx)
	if err != nil {
		if errors.Is(err, errKernelAuditAbsent) {
			return AuditStatus{Present: false}, nil
		}
		return nil, err
	}
	out.Present = true
	backlog := int(st.Backlog)
	lost := int(st.Lost)
	out.QueueDepth = &backlog
	out.LostEvents = &lost

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
		if !errors.Is(err, fs.ErrNotExist) {
			// permission errors and similar fall through; the field
			// being null is the correct signal.
		}
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
