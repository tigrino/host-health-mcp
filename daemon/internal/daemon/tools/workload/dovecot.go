//go:build wl_dovecot

package workload

import (
	"context"

	"host-health-mcp/daemon/internal/daemon/helperinvoke"
	"host-health-mcp/daemon/internal/shared/proto"
)

func init() {
	Register(&dovecotPlugin{})
}

// dovecotPlugin returns process state and connection count by
// delegating to the helper's dovecot_status op. The helper invokes
// `systemctl is-active dovecot.service` for the state and `doveadm
// who -1` for the session count; per-session columns (usernames,
// remote addresses) are not retained, only the line count crosses
// the socket.
type dovecotPlugin struct{}

func (*dovecotPlugin) Name() string { return "dovecot" }

func (*dovecotPlugin) Collect(ctx context.Context, hc *helperinvoke.Client, _ map[string]string) (any, []string, error) {
	var st struct {
		ProcessState    string `json:"process_state"`
		ConnectionCount int    `json:"connection_count"`
		Warning         string `json:"warning,omitempty"`
	}
	if err := hc.CallJSON(ctx, proto.OpDovecotStatus, "", &st); err != nil {
		return nil, nil, err
	}
	var warnings []string
	if st.Warning != "" {
		warnings = append(warnings, st.Warning)
	}
	// Schema is additionalProperties:false; warning lives on the
	// envelope, not in the data map.
	return map[string]any{
		"process_state":    st.ProcessState,
		"connection_count": st.ConnectionCount,
	}, warnings, nil
}
