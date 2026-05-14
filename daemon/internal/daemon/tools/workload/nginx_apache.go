//go:build wl_nginx_apache

package workload

import (
	"context"
	"errors"

	"tigr.net/host-health-mcp/daemon/internal/daemon/helperinvoke"
)

func init() {
	Register(&nginxApachePlugin{})
}

// nginxApachePlugin reports worker count and recent 4xx/5xx counts.
// Today a placeholder; a real implementation reads worker state from
// /proc/<pid>/stat for the daemon's workers and ingests a configured
// access-log summary file (operator-supplied bounded summary; the
// daemon never reads raw access-log bodies, per REQ 6.2).
type nginxApachePlugin struct{}

func (*nginxApachePlugin) Name() string { return "nginx_apache" }

func (*nginxApachePlugin) Collect(ctx context.Context, _ *helperinvoke.Client) (any, error) {
	return nil, errors.New("nginx/apache plugin not yet implemented")
}
