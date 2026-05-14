//go:build wl_postfix

package workload

import (
	"context"
	"errors"

	"tigr.net/host-health-mcp/daemon/internal/daemon/helperinvoke"
	"tigr.net/host-health-mcp/daemon/internal/shared/proto"
)

func init() {
	Register(&postfixPlugin{})
}

// postfixPlugin reports queue depth from the helper's postqueue op
// plus deferred count. Today returns the queue_depth field only;
// deferred-count parsing is a follow-up that may need an additional
// helper op for "postqueue -j" or a deeper parse of "postqueue -p".
type postfixPlugin struct{}

func (*postfixPlugin) Name() string { return "postfix" }

func (*postfixPlugin) Collect(ctx context.Context, hc *helperinvoke.Client) (any, error) {
	var pq struct {
		QueueDepth int `json:"queue_depth"`
	}
	if err := hc.CallJSON(ctx, proto.OpPostqueue, "", &pq); err != nil {
		return nil, err
	}
	if pq.QueueDepth < 0 {
		return nil, errors.New("postqueue returned negative depth")
	}
	return map[string]any{
		"queue_depth":    pq.QueueDepth,
		"deferred_count": 0,
	}, nil
}
