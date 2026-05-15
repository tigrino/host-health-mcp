package ops

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"tigr.net/host-health-mcp/daemon/internal/helper/dispatch"
	helperexec "tigr.net/host-health-mcp/daemon/internal/helper/exec"
	"tigr.net/host-health-mcp/daemon/internal/shared/proto"
)

// AuditStatus is the typed result for op read_audit_status. Mirrors
// the daemon's security.auditd block.
type AuditStatus struct {
	Present         bool       `json:"present"`
	QueueDepth      *int       `json:"queue_depth"`
	LostEvents      *int       `json:"lost_events"`
	LastRotationTS  *time.Time `json:"last_rotation_ts"`
}

// ReadAuditStatus invokes `auditctl -s` and parses the key-value
// status output. Requires CAP_AUDIT_READ on the helper unit (templated
// in at install when security is enabled in manifest). Reports
// present=false when auditctl is not installed; queue_depth and
// lost_events are null when the auditd kernel subsystem is not
// initialised.
func ReadAuditStatus(ctx context.Context, _ string) (any, error) {
	out := AuditStatus{}

	stdout, err := helperexec.Run(ctx, "auditctl", "-s")
	if err != nil {
		var de *dispatch.Error
		if errors.As(err, &de) && de.Code == proto.CodeToolMissing {
			// auditctl truly absent: present=false, no error.
			return AuditStatus{Present: false}, nil
		}
		// auditctl exists but the call failed (kernel audit
		// uninitialised, permission denied, etc.). Surface the
		// failure so the daemon's warnings[] carries it instead of
		// returning a silent Present:false that contradicts the
		// daemon's binary check.
		return nil, err
	}
	out.Present = true

	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "backlog":
			if v, err := strconv.Atoi(fields[1]); err == nil {
				out.QueueDepth = &v
			}
		case "lost":
			if v, err := strconv.Atoi(fields[1]); err == nil {
				out.LostEvents = &v
			}
		}
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
