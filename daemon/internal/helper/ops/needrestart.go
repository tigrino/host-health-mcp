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

// NeedrestartResult is the typed result for op needrestart.
type NeedrestartResult struct {
	PendingServices []string `json:"pending_services"`
}

// Needrestart invokes `needrestart -r l -b -p` and parses the
// NEEDRESTART-SVC: lines from its batch output. The explicit `-r l`
// (list-only) overrides any `$nrconf{restart}` value the operator may
// have set in /etc/needrestart/needrestart.conf; without it, a host
// configured with `$nrconf{restart} = 'a';` would let the batch run
// restart services. REQ 6.1 makes read-only an unconditional
// guarantee, not a property contingent on operator config.
func Needrestart(ctx context.Context, _ string) (any, error) {
	stdout, err := helperexec.Run(ctx, "needrestart", "-r", "l", "-b", "-p")
	if err != nil {
		// needrestart can exit non-zero when there is pending work,
		// per its --help. Surface the failure if there's no parseable
		// output; otherwise prefer what we managed to read.
		if len(stdout) == 0 {
			return nil, err
		}
	}

	out := NeedrestartResult{PendingServices: []string{}}
	scanner := linescan.New(bytes.NewReader(stdout), "needrestart")
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
	if err := scanner.Err(); err != nil {
		return nil, &dispatch.Error{Code: proto.CodeToolFailed, Message: err.Error()}
	}
	return out, nil
}
