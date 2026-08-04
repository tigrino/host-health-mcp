package ops

import (
	"bytes"
	"context"
	"errors"
	"host-health-mcp/daemon/internal/shared/linescan"
	"io"
	"os"
	"strings"
	"time"

	"host-health-mcp/daemon/internal/helper/dispatch"
	helperexec "host-health-mcp/daemon/internal/helper/exec"
	"host-health-mcp/daemon/internal/shared/proto"
)

// UnattendedUpgradesStatusResult is the typed result for op
// unattended_upgrades_status.
type UnattendedUpgradesStatusResult struct {
	Enabled      bool       `json:"enabled"`
	LastRunTS    *time.Time `json:"last_run_ts"`
	LastExitCode *int       `json:"last_exit_code"`
}

const unattendedUpgradesLogPath = "/var/log/unattended-upgrades/unattended-upgrades.log"

// UnattendedUpgradesStatus determines whether unattended-upgrades is
// configured to run (via `apt-config dump` — the authoritative source,
// equivalent to apt's own lookup) and reports the last run timestamp
// + exit code parsed from the script log. The log lives under
// /var/log/unattended-upgrades/ which is root:root 0750 on Debian; the
// daemon user cannot traverse the directory, so this op runs in the
// helper which is root.
func UnattendedUpgradesStatus(ctx context.Context, _ string) (any, error) {
	out := UnattendedUpgradesStatusResult{}

	stdout, err := helperexec.Run(ctx, "apt-config", "dump")
	if err != nil {
		var de *dispatch.Error
		if errors.As(err, &de) && de.Code == proto.CodeToolMissing {
			// apt-config absent: not a Debian-family host. Report
			// not-enabled with no error.
			return out, nil
		}
		return nil, err
	}
	out.Enabled = parseUnattendedFromAptConfig(stdout)

	// Log parsing is best-effort: a host that just installed the
	// package but hasn't run it yet has no log. That is not an error.
	// Log stat is best-effort. If it fails for any reason (file
	// missing, permission denied, dir-traversal race on a
	// slow host where logrotate just ran), keep the
	// apt-config-derived Enabled state and return — failing the
	// whole op would mask Enabled, which IS known.
	info, err := os.Stat(unattendedUpgradesLogPath)
	if err != nil {
		return out, nil
	}
	ts := info.ModTime().UTC()
	out.LastRunTS = &ts

	// Bounded below via io.LimitReader: this log grows unattended (the
	// clue is in the name) and nothing else caps it.
	f, err := os.Open(unattendedUpgradesLogPath)
	if err != nil {
		return out, nil
	}
	defer f.Close()
	// The last exit code lives at the END of the log, so read the tail
	// rather than the whole file.
	if info.Size() > maxUnattendedLogBytes {
		if _, seekErr := f.Seek(info.Size()-maxUnattendedLogBytes, io.SeekStart); seekErr != nil {
			return out, nil
		}
	}
	out.LastExitCode = parseUnattendedLastExitCode(io.LimitReader(f, maxUnattendedLogBytes))
	return out, nil
}

// maxUnattendedLogBytes bounds the tail read of
// unattended-upgrades.log. The file grows without external rotation
// on some hosts and the only field taken from it is the last exit
// code, which is at the end.
const maxUnattendedLogBytes = 4 * 1024 * 1024

// parseUnattendedFromAptConfig returns true if apt-config dump
// reports `APT::Periodic::Unattended-Upgrade "1"`. apt parses files
// under /etc/apt/apt.conf.d/ in lexicographic order with later
// values overriding earlier ones; apt-config dump emits the final
// resolved view, so the parse is straight key-equality on the last
// occurrence.
func parseUnattendedFromAptConfig(b []byte) bool {
	const key = `APT::Periodic::Unattended-Upgrade "`
	last := ""
	scanner := linescan.New(bytes.NewReader(b), "apt-config dump")
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		idx := strings.Index(line, key)
		if idx < 0 {
			continue
		}
		rest := line[idx+len(key):]
		end := strings.IndexByte(rest, '"')
		if end < 0 {
			continue
		}
		last = rest[:end]
	}
	// A truncated read yields a confidently wrong number. Report
	// "unknown" instead — for a health check the two are not the
	// same thing.
	if scanner.Err() != nil {
		return false
	}
	return last == "1"
}

// parseUnattendedLastExitCode scans the unattended-upgrades log from
// the start (the file is small — Debian's logrotate caps it well
// under a MiB) and returns the exit code derived from the most
// recent terminal status line. Conventions per the script source:
//
//	"All upgrades installed"               -> 0
//	"No packages found that can be upgraded unattended" -> 0
//	"Upgrade failed"                       -> 1
//
// Anything else leaves the exit code null.
func parseUnattendedLastExitCode(r io.Reader) *int {
	scanner := linescan.New(r, "unattended-upgrades.log")
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	var lastCode *int
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.Contains(line, "All upgrades installed"),
			strings.Contains(line, "No packages found that can be upgraded unattended"):
			zero := 0
			lastCode = &zero
		case strings.Contains(line, "Upgrade failed"):
			one := 1
			lastCode = &one
		}
	}
	// A truncated read yields a confidently wrong number. Report
	// "unknown" instead — for a health check the two are not the
	// same thing.
	if scanner.Err() != nil {
		return nil
	}
	return lastCode
}
