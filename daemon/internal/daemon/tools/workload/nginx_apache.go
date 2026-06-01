//go:build wl_nginx_apache

package workload

import (
	"context"

	"host-health-mcp/daemon/internal/daemon/helperinvoke"
	"host-health-mcp/daemon/internal/shared/proto"
)

func init() {
	Register(&nginxApachePlugin{})
}

// nginxApachePlugin reports worker count and recent 4xx/5xx counts.
// Worker count is derived from /proc inside the helper (server
// detection by /proc/<pid>/comm); recent error counts come from an
// operator-supplied bounded summary JSON file whose path is taken
// from manifest.workload_plugin_config.nginx_apache.access_log_summary_path.
// The daemon never reads raw access-log bodies (REQ 6.2).
type nginxApachePlugin struct{}

func (*nginxApachePlugin) Name() string { return "nginx_apache" }

func (*nginxApachePlugin) Collect(ctx context.Context, hc *helperinvoke.Client, cfg map[string]string) (any, []string, error) {
	summaryPath := cfg["access_log_summary_path"]

	var st struct {
		Server      string `json:"server"`
		WorkerCount int    `json:"worker_count"`
		Recent4xx   int    `json:"recent_4xx"`
		Recent5xx   int    `json:"recent_5xx"`
		Warning     string `json:"warning,omitempty"`
	}
	if err := hc.CallJSON(ctx, proto.OpNginxApacheStatus, summaryPath, &st); err != nil {
		return nil, nil, err
	}
	var warnings []string
	if st.Warning != "" {
		warnings = append(warnings, st.Warning)
	}
	// Schema is additionalProperties:false; warning lives on the
	// envelope, not in the data map.
	return map[string]any{
		"server":       st.Server,
		"worker_count": st.WorkerCount,
		"recent_4xx":   st.Recent4xx,
		"recent_5xx":   st.Recent5xx,
	}, warnings, nil
}
