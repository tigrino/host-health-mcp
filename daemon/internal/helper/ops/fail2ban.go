package ops

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"

	"tigr.net/host-health-mcp/daemon/internal/helper/dispatch"
	helperexec "tigr.net/host-health-mcp/daemon/internal/helper/exec"
	"tigr.net/host-health-mcp/daemon/internal/shared/proto"
)

// Fail2banStatusResult is the typed result for op fail2ban_status.
type Fail2banStatusResult struct {
	Present     bool `json:"present"`
	JailCount   int  `json:"jail_count"`
	TotalBanned int  `json:"total_banned"`
}

// Fail2banStatus invokes `fail2ban-client status` to list jails and
// then `fail2ban-client status <jail>` for each jail to extract the
// currently-banned count. Returns Present=false when the binary is
// absent rather than failing; that is the operationally useful
// signal for the security tool. Requires read access to
// /var/run/fail2ban/fail2ban.sock which is root-owned on Debian.
func Fail2banStatus(ctx context.Context, _ string) (any, error) {
	out := Fail2banStatusResult{}

	stdout, err := helperexec.Run(ctx, "fail2ban-client", "status")
	if err != nil {
		var de *dispatch.Error
		// fail2ban-client missing → present=false, not an error.
		if errors.As(err, &de) && de.Code == proto.CodeToolMissing {
			return out, nil
		}
		// fail2ban-client exists but the daemon isn't reachable.
		// Surface as a hard failure so the operator notices.
		return nil, err
	}
	out.Present = true

	jails := parseFail2banJailList(stdout)
	out.JailCount = len(jails)

	for _, jail := range jails {
		jailOut, err := helperexec.Run(ctx, "fail2ban-client", "status", jail)
		if err != nil {
			continue
		}
		out.TotalBanned += parseFail2banCurrentlyBanned(jailOut)
	}
	return out, nil
}

// parseFail2banJailList extracts the comma-separated jail names from
// the "Jail list:" line of `fail2ban-client status`.
func parseFail2banJailList(b []byte) []string {
	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, "Jail list:")
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(line[idx+len("Jail list:"):])
		if rest == "" {
			return nil
		}
		fields := strings.Split(rest, ",")
		out := make([]string, 0, len(fields))
		for _, f := range fields {
			name := strings.TrimSpace(f)
			if name != "" {
				out = append(out, name)
			}
		}
		return out
	}
	return nil
}

// parseFail2banCurrentlyBanned extracts the integer after "Currently
// banned:" from a single jail's status output. Returns 0 if absent.
func parseFail2banCurrentlyBanned(b []byte) int {
	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, "Currently banned:")
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(line[idx+len("Currently banned:"):])
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0
		}
		n, err := strconv.Atoi(fields[0])
		if err != nil {
			return 0
		}
		return n
	}
	return 0
}

