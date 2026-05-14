// Package systemdunits implements tool 4.2: state of manifest-
// whitelisted systemd units. Reads via the system D-Bus (no helper
// required - the daemon user can query unit state under standard
// PolicyKit rules). Caller cannot supply unit names.
package systemdunits

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
)

// Data is the response data for tool systemd_units. Mirrors
// the SystemdUnit schema in doc/schema-draft.yaml.
type Data struct {
	Units []Unit `json:"units"`
}

// Unit mirrors the per-unit shape.
type Unit struct {
	Name           string     `json:"name"`
	LoadState      string     `json:"load_state"`
	ActiveState    string     `json:"active_state"`
	SubState       string     `json:"sub_state"`
	Result         string     `json:"result"`
	ExecMainStatus int        `json:"exec_main_status"`
	ActiveEnterTS  *time.Time `json:"active_enter_ts"`
	ActiveExitTS   *time.Time `json:"active_exit_ts"`
	RestartCount   int        `json:"restart_count"`
}

// Tool is the registered tool.
type Tool struct {
	// whitelisted is the manifest-declared set of units to report on.
	// The daemon must not return state for any unit not in this list
	// (REQ 4.2).
	whitelisted []string
}

// New returns a new tool instance over the manifest-supplied whitelist.
func New(whitelisted []string) *Tool {
	w := make([]string, len(whitelisted))
	copy(w, whitelisted)
	return &Tool{whitelisted: w}
}

// Name returns the tool name.
func (*Tool) Name() string { return "systemd_units" }

// DefaultTTL: unit state changes are infrequent on a healthy host.
func (*Tool) DefaultTTL() time.Duration { return 15 * time.Second }

// DefaultTimeout caps the per-call duration.
func (*Tool) DefaultTimeout() time.Duration { return 3 * time.Second }

// Handle queries the system bus for each whitelisted unit's basic
// state plus the small set of properties REQ 4.2 specifies.
func (t *Tool) Handle(ctx context.Context, _ []byte) (any, []string, error) {
	if len(t.whitelisted) == 0 {
		return Data{Units: []Unit{}}, nil, nil
	}

	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("dbus: %w", err)
	}
	defer conn.Close()

	listed, err := conn.ListUnitsByNamesContext(ctx, t.whitelisted)
	if err != nil {
		return nil, nil, fmt.Errorf("dbus list: %w", err)
	}

	out := Data{Units: make([]Unit, 0, len(listed))}
	for _, u := range listed {
		entry := Unit{
			Name:        u.Name,
			LoadState:   u.LoadState,
			ActiveState: u.ActiveState,
			SubState:    u.SubState,
		}
		// Detailed properties live on the unit's object path. The
		// systemd API exposes Service-typed properties under the
		// Service interface; for non-Service units some keys (Result,
		// ExecMainStatus, RestartCount) simply don't exist and are
		// returned as their zero values.
		props, perr := conn.GetUnitTypePropertiesContext(ctx, u.Name, "Service")
		if perr == nil {
			if v, ok := props["Result"].(string); ok {
				entry.Result = v
			}
			if v, ok := props["ExecMainStatus"].(int32); ok {
				entry.ExecMainStatus = int(v)
			}
			if v, ok := props["NRestarts"].(uint32); ok {
				entry.RestartCount = int(v)
			}
		}
		unitProps, uerr := conn.GetUnitPropertiesContext(ctx, u.Name)
		if uerr == nil {
			if v, ok := unitProps["ActiveEnterTimestamp"].(uint64); ok && v > 0 {
				ts := time.UnixMicro(int64(v)).UTC()
				entry.ActiveEnterTS = &ts
			}
			if v, ok := unitProps["ActiveExitTimestamp"].(uint64); ok && v > 0 {
				ts := time.UnixMicro(int64(v)).UTC()
				entry.ActiveExitTS = &ts
			}
		}
		out.Units = append(out.Units, entry)
	}
	return out, nil, nil
}
