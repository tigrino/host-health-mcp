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

// PostqueueResult is the typed result for op postqueue.
type PostqueueResult struct {
	QueueDepth    int `json:"queue_depth"`
	DeferredCount int `json:"deferred_count"`
}

// Postqueue invokes `postqueue -p`. The trailing summary line gives
// the total queue depth; per-message header lines are counted to
// derive the deferred subtotal. We never read the envelope-address
// columns nor retain queue identifiers — the security-hygiene
// constraint here is: only the columns this function explicitly
// consumes (queue-id token first char-set, indicator suffix, size
// column) may enter parser memory; sender, recipient, and any other
// envelope detail must be ignored on the same forward pass.
func Postqueue(ctx context.Context, _ string) (any, error) {
	stdout, err := helperexec.Run(ctx, "postqueue", "-p")
	if err != nil {
		return nil, err
	}
	res, perr := parsePostqueueOutput(stdout)
	if perr != nil {
		return nil, &dispatch.Error{Code: proto.CodeToolFailed, Message: perr.Error()}
	}
	return res, nil
}

// maxQueueDepth clamps the reported queue depth. Postfix will not
// hold anywhere near this many messages before other limits bite.
const maxQueueDepth = 10_000_000

// parsePostqueueOutput is the pure parser exposed for testing.
// QueueDepth comes from the trailing "-- N Kbytes in M Requests."
// summary; DeferredCount is counted per-message from the indicator
// suffix on each queue-id header line (no suffix == deferred, '*' ==
// active, '!' == hold).
func parsePostqueueOutput(stdout []byte) (PostqueueResult, error) {
	out := PostqueueResult{}
	scanner := linescan.New(bytes.NewReader(stdout), "postqueue -p")
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Mail queue is empty") {
			return out, nil
		}
		if strings.HasPrefix(line, "--") && strings.Contains(line, "Requests") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "in" && i+1 < len(fields) {
					var n int
					for _, c := range fields[i+1] {
						if c < '0' || c > '9' {
							break
						}
						n = n*10 + int(c-'0')
					}
					// Clamp. n comes from postqueue's own summary line,
					// but that line is derived from queue contents an
					// external sender influences; a 64-bit value here
					// would overflow anything downstream that narrows
					// it, and a negative depth is meaningless.
					if n < 0 {
						n = 0
					}
					if n > maxQueueDepth {
						n = maxQueueDepth
					}
					out.QueueDepth = n
					// Do not return here — defer counting may
					// happen on lines either side of the summary.
					// The summary occurs once at the end on real
					// postqueue output, so the loop naturally
					// terminates after this scan.
					continue
				}
			}
			continue
		}
		if isDeferredHeaderLine(line) {
			out.DeferredCount++
		}
	}
	if err := scanner.Err(); err != nil {
		return PostqueueResult{}, err
	}
	return out, nil
}

// isDeferredHeaderLine identifies a deferred-message header row. The
// first whitespace-delimited token is a 10–15 character queue id
// composed of [A-Za-z0-9] with optionally exactly one of '*' or '!'
// appended; '*' means active and '!' means hold — neither is
// deferred. The second token must be numeric (the size column). The
// header row "-Queue ID-..." starts with '-' which fails the
// alphanumeric requirement; continuation lines start with whitespace
// and never have a first token at all under strings.Fields.
func isDeferredHeaderLine(line string) bool {
	if line == "" {
		return false
	}
	if line[0] == ' ' || line[0] == '\t' {
		return false
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	tok := fields[0]
	// Strip trailing indicator (if any) and decide deferred-ness.
	deferred := true
	last := tok[len(tok)-1]
	if last == '*' || last == '!' {
		deferred = false
		tok = tok[:len(tok)-1]
	}
	if len(tok) < 10 || len(tok) > 15 {
		return false
	}
	for _, c := range tok {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}
	// Size column must be a non-negative integer.
	size := fields[1]
	if size == "" {
		return false
	}
	for _, c := range size {
		if c < '0' || c > '9' {
			return false
		}
	}
	return deferred
}
