//go:build wl_postfix

package workload

import (
	"context"
	"errors"
	"fmt"

	"host-health-mcp/daemon/internal/daemon/helperinvoke"
	"host-health-mcp/daemon/internal/shared/proto"
)

func init() {
	Register(&postfixPlugin{})
}

// postfixPlugin reports queue depth plus deferred count from the
// helper's postqueue op. The helper parses `postqueue -p` and returns
// typed counts only; envelope addresses and queue identifiers are not
// retained on either side of the socket (design §7.3).
type postfixPlugin struct{}

func (*postfixPlugin) Name() string { return "postfix" }

func (*postfixPlugin) Collect(ctx context.Context, hc *helperinvoke.Client, _ map[string]string) (any, []string, error) {
	var pq struct {
		QueueDepth    int `json:"queue_depth"`
		DeferredCount int `json:"deferred_count"`
	}
	if err := hc.CallJSON(ctx, proto.OpPostqueue, "", &pq); err != nil {
		return nil, nil, err
	}
	if pq.QueueDepth < 0 {
		return nil, nil, errors.New("postqueue returned negative depth")
	}
	if pq.DeferredCount < 0 {
		return nil, nil, errors.New("postqueue returned negative deferred count")
	}
	var warnings []string
	// Defence-in-depth: helper-side parser counts deferred messages by
	// scanning headers while the total is read from the trailer; these
	// two views agree on well-formed `postqueue -p` output but a
	// truncated capture or a postfix version with an unexpected output
	// shape could disagree. Surface as a warning rather than fail.
	if pq.DeferredCount > pq.QueueDepth {
		warnings = append(warnings, fmt.Sprintf("deferred_count > queue_depth (postqueue reported %d > %d); clamping", pq.DeferredCount, pq.QueueDepth))
		pq.DeferredCount = pq.QueueDepth
	}
	return map[string]any{
		"queue_depth":    pq.QueueDepth,
		"deferred_count": pq.DeferredCount,
	}, warnings, nil
}
