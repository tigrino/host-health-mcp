package ops

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"

	"host-health-mcp/daemon/internal/helper/dispatch"
	helperexec "host-health-mcp/daemon/internal/helper/exec"
	"host-health-mcp/daemon/internal/shared/proto"
)

// DovecotStatusResult is the typed result for op dovecot_status. The
// helper does not enumerate per-session usernames or remote addresses;
// only the count of active sessions crosses the socket (REQ 6.2).
// Warning carries a partial-data condition (e.g. systemd says active
// but doveadm who failed); the daemon strips this field from the
// caller-facing payload and surfaces it as a plugin-level warning.
type DovecotStatusResult struct {
	ProcessState    string `json:"process_state"`
	ConnectionCount int    `json:"connection_count"`
	Warning         string `json:"warning,omitempty"`
}

// Recognised process_state values mirror systemctl's is-active output
// plus a synthetic "not_installed" for the unit-not-found case. Any
// other systemctl output collapses to "unknown".
var dovecotKnownStates = map[string]bool{
	"active":       true,
	"inactive":     true,
	"failed":       true,
	"activating":   true,
	"deactivating": true,
	"unknown":      true,
}

// DovecotStatus derives the dovecot process state from `systemctl
// is-active dovecot.service` and the connection count from `doveadm
// who -1`. Both subprocess invocations route through helperexec.Run;
// neither tool's stderr nor any per-session columns are retained.
func DovecotStatus(ctx context.Context, _ string) (any, error) {
	out := DovecotStatusResult{ProcessState: "unknown"}

	// systemctl is-active returns non-zero for everything except
	// "active" — well-known quirk. Read stdout regardless of err.
	stdout, err := helperexec.Run(ctx, "systemctl", "is-active", "dovecot.service")
	state := strings.TrimSpace(string(stdout))
	if err != nil {
		var de *dispatch.Error
		if errors.As(err, &de) {
			switch de.Code {
			case proto.CodeToolMissing:
				out.ProcessState = "not_installed"
				return out, nil
			case proto.CodeToolFailed:
				// Unit-not-found vs. genuine non-active. systemctl
				// 246+ writes "Unit dovecot.service could not be
				// found." (or similar) to stderr and prints
				// "inactive" on stdout with exit 4.
				if state == "inactive" && strings.Contains(de.StderrPrefix, "could not be found") {
					out.ProcessState = "not_installed"
					return out, nil
				}
				// Fall through: state may still be a recognised
				// systemctl token (inactive/failed/activating/...).
			default:
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	if dovecotKnownStates[state] {
		out.ProcessState = state
	}

	// doveadm who -1: one line per session. Non-zero exit indicates
	// dovecot's auth socket is unreachable; the process_state already
	// carries the diagnostic, so the connection count falls back to 0
	// without surfacing an error from this op. If systemd reports the
	// unit active but doveadm still fails, the data is genuinely
	// partial (cannot tell idle from broken-auth-socket); surface
	// that ambiguity as a warning so the operator does not read a
	// zero count as definitive.
	whoOut, whoErr := helperexec.Run(ctx, "doveadm", "who", "-1")
	if whoErr != nil {
		if out.ProcessState == "active" {
			out.Warning = "doveadm who failed: " + whoErr.Error()
		}
		return out, nil
	}
	out.ConnectionCount = parseDoveadmWho(whoOut)
	return out, nil
}

// parseDoveadmWho counts non-empty session lines, skipping an
// optional header row. doveadm who -1 typically does not emit a
// header, but old versions may. The header is detected by checking
// whether the first non-empty line's first token is the literal
// "username" (case-insensitive).
func parseDoveadmWho(b []byte) int {
	count := 0
	first := true
	scanner := bufio.NewScanner(bytes.NewReader(b))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " \t")
		if line == "" {
			continue
		}
		if first {
			first = false
			fields := strings.Fields(line)
			// Header detection: doveadm who -1's header is
			// "username        # proto ..." — at minimum the first
			// two whitespace-delimited tokens are "username" and
			// "#". A session line for a user literally named
			// "username" still has a numeric session count rather
			// than "#" in the second column.
			if len(fields) >= 2 && strings.EqualFold(fields[0], "username") && fields[1] == "#" {
				continue
			}
		}
		count++
	}
	return count
}
