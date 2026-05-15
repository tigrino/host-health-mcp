// Package backup implements tool 4.8: last_start_ts, last_end_ts,
// last_exit_code, last_archive_label, backend. Reads the manifest-
// declared backup log path's mtime as a coarse signal. Repository
// URLs, passphrases, credentials, and archive contents never appear
// (REQ 4.8).
package backup

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"
)

// Data is the response data for tool backup. data is null when no
// backup is configured (REQ 4.8: returns data: null with a "not-
// configured" warning); the daemon's tool layer handles the null
// case by returning a typed empty wrapper here and relying on the
// envelope's data field to be exactly that struct.
type Data struct {
	Backend            string     `json:"backend"`
	LastStartTS        *time.Time `json:"last_start_ts"`
	LastEndTS          *time.Time `json:"last_end_ts"`
	LastExitCode       *int       `json:"last_exit_code"`
	LastArchiveLabel   *string    `json:"last_archive_label"`
}

// Tool is the registered tool.
type Tool struct {
	logPath string
	backend string
}

// New returns a new tool instance.
func New(logPath, backend string) *Tool {
	if backend == "" {
		backend = "none"
	}
	return &Tool{logPath: logPath, backend: backend}
}

// Name returns the tool name.
func (*Tool) Name() string { return "backup" }

// DefaultTTL: backup runs are infrequent.
func (*Tool) DefaultTTL() time.Duration { return 5 * time.Minute }

// DefaultTimeout caps the per-call duration.
func (*Tool) DefaultTimeout() time.Duration { return 2 * time.Second }

// backendLogProbes lists well-known log paths by backend so an
// operator who sets backup_backend but leaves backup_log_path null
// still gets a useful answer. There is no system-wide convention for
// backup log locations, so the probe is best-effort.
var backendLogProbes = map[string][]string{
	"borg": {
		"/var/log/borg/borg.log",
		"/var/log/borgbackup.log",
		"/var/log/borgmatic/borgmatic.log",
		"/var/log/borgmatic.log",
	},
	"borgmatic": {
		"/var/log/borgmatic/borgmatic.log",
		"/var/log/borgmatic.log",
	},
	"restic": {
		"/var/log/restic.log",
		"/var/log/restic/restic.log",
	},
	"rsnapshot": {
		"/var/log/rsnapshot.log",
		"/var/log/rsnapshot/rsnapshot.log",
	},
	"duplicity": {
		"/var/log/duplicity.log",
	},
}

// Handle stats the manifest-declared log path. When the manifest's
// backup_log_path is empty, the tool attempts well-known paths for
// the configured backend (borg, restic, rsnapshot, duplicity);
// finding nothing is reported as a warning rather than an error so
// the rest of the response remains useful. Last_archive_label is
// only filled when the operator's runner records one in a fixed
// location; today it stays null.
func (t *Tool) Handle(ctx context.Context, _ []byte) (any, []string, error) {
	if t.backend == "none" {
		return Data{Backend: "none"}, []string{"backup: not configured (backup_backend=none)"}, nil
	}
	var warnings []string
	d := Data{Backend: t.backend}

	path := t.logPath
	if path == "" {
		probed, candidates := probeBackendLog(t.backend)
		if probed != "" {
			path = probed
			warnings = append(warnings,
				"backup: auto-probed log path "+probed+
					" (set backup_log_path in manifest.yml to pin)")
		} else if len(candidates) > 0 {
			warnings = append(warnings,
				"backup: log path not configured; tried "+
					strings.Join(candidates, ", ")+
					"; set backup_log_path in manifest.yml")
			return d, warnings, nil
		} else {
			warnings = append(warnings,
				"backup: log path not configured and no auto-probe paths defined for backend "+t.backend)
			return d, warnings, nil
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			warnings = append(warnings, "backup: log path absent: "+path)
			return d, warnings, nil
		}
		return nil, nil, err
	}
	ts := info.ModTime().UTC()
	d.LastEndTS = &ts
	return d, warnings, nil
}

// probeBackendLog returns the first path under backendLogProbes[backend]
// that exists, plus the full candidate list (for the operator-facing
// warning when nothing matches).
func probeBackendLog(backend string) (path string, candidates []string) {
	candidates = backendLogProbes[backend]
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, candidates
		}
	}
	return "", candidates
}
