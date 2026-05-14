package ops

import (
	"bufio"
	"bytes"
	"context"
	"strings"

	helperexec "tigr.net/host-health-mcp/daemon/internal/helper/exec"
)

// NeedrestartResult is the typed result for op needrestart.
type NeedrestartResult struct {
	PendingServices []string `json:"pending_services"`
}

// Needrestart invokes `needrestart -b -p` and parses the
// NEEDRESTART-SVC: lines from its batch output.
func Needrestart(ctx context.Context, _ string) (any, error) {
	stdout, err := helperexec.Run(ctx, "needrestart", "-b", "-p")
	if err != nil {
		// needrestart can exit non-zero when there is pending work,
		// per its --help. Surface the failure if there's no parseable
		// output; otherwise prefer what we managed to read.
		if len(stdout) == 0 {
			return nil, err
		}
	}

	out := NeedrestartResult{PendingServices: []string{}}
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "NEEDRESTART-SVC:") {
			continue
		}
		svc := strings.TrimSpace(strings.TrimPrefix(line, "NEEDRESTART-SVC:"))
		if svc != "" {
			out.PendingServices = append(out.PendingServices, svc)
		}
	}
	return out, nil
}
