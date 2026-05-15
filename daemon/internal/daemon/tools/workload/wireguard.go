//go:build wl_wireguard

package workload

import (
	"context"

	"host-health-mcp/daemon/internal/daemon/helperinvoke"
	"host-health-mcp/daemon/internal/shared/proto"
)

func init() {
	Register(&wireguardPlugin{})
}

// wireguardPlugin satisfies the Plugin interface by delegating to the
// helper's wireguard_show op. The helper does the parse and strips
// private and preshared keys per design §7.3.1; the daemon receives
// only typed, public-key-only data.
type wireguardPlugin struct{}

func (*wireguardPlugin) Name() string { return "wireguard" }

func (*wireguardPlugin) Collect(ctx context.Context, hc *helperinvoke.Client) (any, error) {
	var result map[string]any
	if err := hc.CallJSON(ctx, proto.OpWireguardShow, "", &result); err != nil {
		return nil, err
	}
	return result, nil
}
