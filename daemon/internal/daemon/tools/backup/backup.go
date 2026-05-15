// Package backup implements tool 4.8: last_start_ts, last_end_ts,
// last_exit_code, last_archive_label, backend. Reads the manifest-
// declared backup log path's mtime as a coarse signal. Repository
// URLs, passphrases, credentials, and archive contents never appear
// (REQ 4.8).
package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// defaultStatePath is the documented contract location for the
// operator's backup wrapper to deposit its state file. The wrapper
// writes this file as its last step; the daemon reads it as the
// authoritative source of last_archive_label, exit code, and
// timestamps. Backend-agnostic.
const defaultStatePath = "/var/lib/host-health-mcp/backup-state.json"

// Tool is the registered tool.
type Tool struct {
	logPath   string
	backend   string
	statePath string
}

// New returns a new tool instance. statePath defaults to
// defaultStatePath when empty; setting it explicitly in the manifest
// (backup_state_path) is for operators who deploy the wrapper-state
// file under a non-default location.
func New(logPath, backend, statePath string) *Tool {
	if backend == "" {
		backend = "none"
	}
	if statePath == "" {
		statePath = defaultStatePath
	}
	return &Tool{logPath: logPath, backend: backend, statePath: statePath}
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

// stateFile is the JSON shape the operator's backup wrapper deposits
// at backup_state_path. All fields are optional; the daemon emits the
// envelope with whatever fields are present.
type stateFile struct {
	LastStartTS      *time.Time `json:"last_start_ts"`
	LastEndTS        *time.Time `json:"last_end_ts"`
	LastExitCode     *int       `json:"last_exit_code"`
	LastArchiveLabel *string    `json:"last_archive_label"`
}

// Handle resolves backup state via, in order:
//   1. the wrapper-emitted state file (defaultStatePath or manifest's
//      backup_state_path);
//   2. the manifest-declared log path, or an auto-probed log path for
//      the configured backend;
//   3. nothing matches → warning, all fields null.
// last_archive_label is only ever populated from the state file.
func (t *Tool) Handle(ctx context.Context, _ []byte) (any, []string, error) {
	if t.backend == "none" {
		return Data{Backend: "none"}, []string{"backup: not configured (backup_backend=none)"}, nil
	}
	var warnings []string
	d := Data{Backend: t.backend}

	if state, used, err := readStateFile(t.statePath); err != nil {
		// State file present but malformed — surface and fall through
		// to the log-path branch so the operator at least gets the log
		// timestamp.
		warnings = append(warnings, "backup: state file "+t.statePath+" parse: "+err.Error())
	} else if used {
		d.LastStartTS = state.LastStartTS
		d.LastEndTS = state.LastEndTS
		d.LastExitCode = state.LastExitCode
		d.LastArchiveLabel = state.LastArchiveLabel
		return d, warnings, nil
	}

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

// readStateFile loads the wrapper-emitted state file at path.
// Returns used=false when the file does not exist (a missing state
// file is the expected case for operators who haven't instrumented
// their wrapper yet — fall through to the log-path branch).
func readStateFile(path string) (s stateFile, used bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return stateFile{}, false, nil
		}
		return stateFile{}, false, err
	}
	defer f.Close()
	// Cap at 32 KiB; the file is a handful of fields.
	body, err := io.ReadAll(io.LimitReader(f, 32*1024))
	if err != nil {
		return stateFile{}, false, fmt.Errorf("read: %w", err)
	}
	if err := json.Unmarshal(body, &s); err != nil {
		return stateFile{}, false, fmt.Errorf("json: %w", err)
	}
	return s, true, nil
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
