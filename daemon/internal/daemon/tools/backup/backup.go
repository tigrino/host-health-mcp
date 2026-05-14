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

// Handle stats the manifest-declared log path. Last_archive_label is
// only filled when the operator's runner records one in a fixed
// location; today we leave it null - a follow-up reads it from a
// configurable status file.
func (t *Tool) Handle(ctx context.Context, _ []byte) (any, []string, error) {
	if t.logPath == "" || t.backend == "none" {
		return Data{Backend: "none"}, []string{"backup: not configured"}, nil
	}
	var warnings []string
	d := Data{Backend: t.backend}

	info, err := os.Stat(t.logPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			warnings = append(warnings, "backup: log path absent: "+t.logPath)
			return d, warnings, nil
		}
		return nil, nil, err
	}
	ts := info.ModTime().UTC()
	d.LastEndTS = &ts
	return d, warnings, nil
}
