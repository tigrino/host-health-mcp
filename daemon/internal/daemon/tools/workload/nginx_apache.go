//go:build wl_nginx_apache

package workload

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"host-health-mcp/daemon/internal/daemon/helperinvoke"
	"host-health-mcp/daemon/internal/shared/proto"
)

// maxAccessLogTailBytes mirrors the helper's own ceiling so the
// manifest is validated where the operator can act on the message.
const maxAccessLogTailBytes = 4 * 1024 * 1024

func init() {
	Register(&nginxApachePlugin{})
}

// nginxApachePlugin reports worker count and recent 4xx/5xx counts.
// Server detection runs inside the helper via /proc/<pid>/comm; the
// recent error counts come from a bounded tail-read of the access
// log performed entirely inside the helper process. Raw log bytes
// never cross the helper-to-daemon socket (REQ 6.2). Per-host config
// keys live under manifest.workload_plugin_config.nginx_apache.
type nginxApachePlugin struct{}

func (*nginxApachePlugin) Name() string { return "nginx_apache" }

func (*nginxApachePlugin) Collect(ctx context.Context, hc *helperinvoke.Client, cfg map[string]string) (any, []string, error) {
	var warnings []string

	param := struct {
		AccessLogPath      string `json:"access_log_path"`
		AccessLogWindowMin int    `json:"access_log_window_minutes"`
		AccessLogTailBytes int    `json:"access_log_tail_bytes"`
	}{
		AccessLogPath: cfg["access_log_path"],
	}
	if s := cfg["access_log_window_minutes"]; s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 1 || v > 1440 {
			return nil, nil, fmt.Errorf("nginx_apache: access_log_window_minutes: %q must be an integer in 1..1440", s)
		}
		param.AccessLogWindowMin = v
	}
	if s := cfg["access_log_tail_bytes"]; s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 0 {
			return nil, nil, fmt.Errorf("nginx_apache: access_log_tail_bytes: %q is not a non-negative integer", s)
		}
		// Bound it here as well as in the helper. The helper clamps and
		// warns, but a manifest asking for 4 GiB is a configuration
		// mistake the operator should be told about at the daemon,
		// where the manifest is theirs to fix.
		if v > maxAccessLogTailBytes {
			return nil, nil, fmt.Errorf("nginx_apache: access_log_tail_bytes %d exceeds the %d-byte maximum", v, maxAccessLogTailBytes)
		}
		param.AccessLogTailBytes = v
	}
	paramBytes, err := json.Marshal(param)
	if err != nil {
		return nil, nil, fmt.Errorf("nginx_apache: marshal param: %w", err)
	}

	var st struct {
		Server              string `json:"server"`
		WorkerCount         int    `json:"worker_count"`
		Recent4xx           *int   `json:"recent_4xx"`
		Recent5xx           *int   `json:"recent_5xx"`
		RecentWindowMinutes int    `json:"recent_window_minutes"`
		RecentCoverage      string `json:"recent_coverage"`
		Warning             string `json:"warning,omitempty"`
	}
	if err := hc.CallJSON(ctx, proto.OpNginxApacheStatus, string(paramBytes), &st); err != nil {
		return nil, nil, err
	}
	if st.Warning != "" {
		warnings = append(warnings, st.Warning)
	}
	// Schema is additionalProperties:false; warning lives on the
	// envelope, not in the data map. Recent4xx / Recent5xx are kept
	// as *int so JSON null is preserved when the helper could not
	// measure (null != measured zero on the wire).
	return map[string]any{
		"server":                st.Server,
		"worker_count":          st.WorkerCount,
		"recent_4xx":            st.Recent4xx,
		"recent_5xx":            st.Recent5xx,
		"recent_window_minutes": st.RecentWindowMinutes,
		"recent_coverage":       st.RecentCoverage,
	}, warnings, nil
}
