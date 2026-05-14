package ops

import (
	"bufio"
	"bytes"
	"context"
	"strings"

	helperexec "tigr.net/host-health-mcp/daemon/internal/helper/exec"
)

// PostqueueResult is the typed result for op postqueue.
type PostqueueResult struct {
	QueueDepth int `json:"queue_depth"`
}

// Postqueue invokes `postqueue -p` and counts queued messages. The
// output trailer is one of:
//   "-- 0 Kbytes in 0 Requests."
//   "Mail queue is empty"
// We parse the trailing summary rather than per-message lines so that
// the helper never holds queue identifiers or envelope addresses in
// memory.
func Postqueue(ctx context.Context, _ string) (any, error) {
	stdout, err := helperexec.Run(ctx, "postqueue", "-p")
	if err != nil {
		return nil, err
	}

	out := PostqueueResult{}
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Mail queue is empty") {
			out.QueueDepth = 0
			return out, nil
		}
		if strings.HasPrefix(line, "--") && strings.Contains(line, "Requests") {
			fields := strings.Fields(line)
			// Expected: "-- <kbytes> Kbytes in <count> Requests."
			for i, f := range fields {
				if f == "in" && i+1 < len(fields) {
					var n int
					for _, c := range fields[i+1] {
						if c < '0' || c > '9' {
							break
						}
						n = n*10 + int(c-'0')
					}
					out.QueueDepth = n
					return out, nil
				}
			}
		}
	}
	return out, nil
}
