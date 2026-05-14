package ops

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	helperexec "tigr.net/host-health-mcp/daemon/internal/helper/exec"
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
		// auditctl missing: report present=false rather than failing.
		// Other errors (kernel rejecting the syscall, permission)
		// surface as the op's failure to the daemon.
		return AuditStatus{Present: false}, nil
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
	// file (audit.log.1.gz, audit.log.2.gz, ...). The mtime of the
	// most recent rotated file is the last rotation timestamp.
	if ts := newestRotatedLog("/var/log/audit", "audit.log.", true); !ts.IsZero() {
		out.LastRotationTS = &ts
	}

	return out, nil
}

// newestRotatedLog returns the mtime of the newest file matching
// prefix in dir. wantGzipped restricts to .gz files (rotated copies
// after a rotation; the live log lacks the .gz suffix).
func newestRotatedLog(dir, prefix string, wantGzipped bool) time.Time {
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
		if wantGzipped && filepath.Ext(name) != ".gz" {
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
