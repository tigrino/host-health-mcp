package ops

import (
	"bytes"
	"context"
	"host-health-mcp/daemon/internal/helper/dispatch"
	"host-health-mcp/daemon/internal/shared/linescan"
	"host-health-mcp/daemon/internal/shared/proto"
	"strings"

	helperexec "host-health-mcp/daemon/internal/helper/exec"
)

// AptPendingResult is the typed result for op apt_pending. Mirrors the
// daemon-side schema for tool 4.12: only the slice of fields the
// helper actually produces; the daemon's tool layer composes the full
// UpdatesData envelope from this plus reads from the daemon's own
// filesystem (apt indices, /var/lib/apt/periodic).
type AptPendingResult struct {
	LockState              string   `json:"lock_state"`
	SecurityUpdatesPending *int     `json:"security_updates_pending"`
	RegularUpdatesPending  *int     `json:"regular_updates_pending"`
	HeldPackages           []string `json:"held_packages"`
}

// AptPending invokes `apt-get -s upgrade` and parses its output.
// When the dpkg frontend lock is held by another process, apt-get
// returns non-zero with a diagnostic on stderr; the helper reports
// lock_state=contended and null counts. Other dpkg holds (`dpkg
// --get-selections | grep hold`) are read via dpkg --get-selections
// rather than apt.
func AptPending(ctx context.Context, _ string) (any, error) {
	out := AptPendingResult{
		LockState:    "acquired",
		HeldPackages: []string{},
	}

	upgradeOut, err := helperexec.Run(ctx, "apt-get", "-s", "upgrade")
	if err != nil {
		out.LockState = "contended"
		return out, nil
	}

	sec, reg, perr := countUpgrades(upgradeOut)
	if perr != nil {
		// An understated pending-update count reads as "this host is
		// patched" — the opposite of the truth.
		return nil, &dispatch.Error{Code: proto.CodeToolFailed, Message: perr.Error()}
	}
	out.SecurityUpdatesPending = &sec
	out.RegularUpdatesPending = &reg

	holdOut, err := helperexec.Run(ctx, "dpkg", "--get-selections")
	if err == nil {
		held, herr := extractHeld(holdOut)
		if herr != nil {
			return nil, &dispatch.Error{Code: proto.CodeToolFailed, Message: herr.Error()}
		}
		out.HeldPackages = held
	}

	return out, nil
}

// countUpgrades returns (security-pending, regular-pending) from
// `apt-get -s upgrade` output. The simulation prefixes upgrade lines
// with "Inst <pkg> [...] (Debian:<dist>/<archive>" where archive
// containing "security" marks the upgrade as a security update.
func countUpgrades(b []byte) (sec, reg int, err error) {
	scanner := linescan.New(bytes.NewReader(b), "apt")
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		if strings.Contains(line, "security") {
			sec++
		} else {
			reg++
		}
	}
	if err = scanner.Err(); err != nil {
		return 0, 0, err
	}
	return sec, reg, nil
}

// extractHeld scans dpkg --get-selections output for lines whose status
// is "hold". Each line is "<name>\t<status>".
func extractHeld(b []byte) ([]string, error) {
	var held []string
	scanner := linescan.New(bytes.NewReader(b), "apt")
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == "hold" {
			held = append(held, fields[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return held, nil
}
