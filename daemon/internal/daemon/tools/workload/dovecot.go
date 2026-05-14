//go:build wl_dovecot

package workload

import (
	"context"
	"errors"

	"tigr.net/host-health-mcp/daemon/internal/daemon/helperinvoke"
)

func init() {
	Register(&dovecotPlugin{})
}

// dovecotPlugin returns process state and connection count. Today is a
// build-tag-gated placeholder; a real implementation reads
// /var/run/dovecot/master.fifo state and queries the
// `doveadm director status` interface (root-only, helper-side).
type dovecotPlugin struct{}

func (*dovecotPlugin) Name() string { return "dovecot" }

func (*dovecotPlugin) Collect(ctx context.Context, _ *helperinvoke.Client) (any, error) {
	return nil, errors.New("dovecot plugin not yet implemented")
}
