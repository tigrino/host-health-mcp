package ops

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
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
	info, err := os.Stat(unattendedUpgradesLogPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return out, nil
		}
		return nil, err
	}
	ts := info.ModTime().UTC()
	out.LastRunTS = &ts

	f, err := os.Open(unattendedUpgradesLogPath)
	if err != nil {
		return out, nil
	}
	defer f.Close()
	out.LastExitCode = parseUnattendedLastExitCode(f)
	return out, nil
}

// parseUnattendedFromAptConfig returns true if apt-config dump
// reports `APT::Periodic::Unattended-Upgrade "1"`. apt parses files
// under /etc/apt/apt.conf.d/ in lexicographic order with later
// values overriding earlier ones; apt-config dump emits the final
// resolved view, so the parse is straight key-equality on the last
// occurrence.
func parseUnattendedFromAptConfig(b []byte) bool {
	const key = `APT::Periodic::Unattended-Upgrade "`
	last := ""
	scanner := bufio.NewScanner(bytes.NewReader(b))
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
	return last == "1"
}

// parseUnattendedLastExitCode scans the unattended-upgrades log from
// the start (the file is small — Debian's logrotate caps it well
// under a MiB) and returns the exit code derived from the most
// recent terminal status line. Conventions per the script source:
//   "All upgrades installed"               -> 0
//   "No packages found that can be upgraded unattended" -> 0
//   "Upgrade failed"                       -> 1
// Anything else leaves the exit code null.
func parseUnattendedLastExitCode(r io.Reader) *int {
	scanner := bufio.NewScanner(r)
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
	return lastCode
}
