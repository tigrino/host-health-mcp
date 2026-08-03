// Package systemdunits implements tool 4.2: state of manifest-
// whitelisted systemd units. Reads via the system D-Bus (no helper
// required - the daemon user can query unit state under standard
// PolicyKit rules). Caller cannot supply unit names or patterns; the
// selector is whitelisted_units (exact) plus whitelisted_unit_patterns
// (globs) from manifest.yml, both operator-controlled.
package systemdunits

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
)

// Data is the response data for tool systemd_units. Mirrors
// the SystemdUnit schema in doc/schema-draft.yaml.
//
// The two selectors stay in separate arrays rather than merging. That
// keeps the change additive by construction — a consumer written
// before 2.2.0 reads Units and sees exactly what it saw before, so
// pattern-discovered units cannot leak into an existing alert rule
// unless it opts in — and it preserves a real operational distinction:
// a not-found row in Units means an operator-declared unit is missing
// and is worth alerting on, whereas a unit leaving PatternUnits is
// usually routine (php8.2-fpm superseded by php8.3-fpm).
type Data struct {
	// Units holds the exact selector's results, including the
	// not-found rows systemd synthesises for unrecognised names.
	Units []Unit `json:"units"`
	// PatternUnits holds the glob selector's results, disjoint from
	// Units: a unit both named and matched appears only in Units.
	PatternUnits []Unit `json:"pattern_units"`
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
	// patterns is the glob half of the same selector, resolved through
	// systemd's own matcher so behaviour tracks
	// `systemctl list-units '<pattern>'` exactly instead of drifting
	// from a reimplementation.
	patterns []string
}

// maxPatternUnits bounds the glob selector's result. Each unit costs
// two further D-Bus round trips below, against a 3s budget, so a broad
// pattern like "*.service" would otherwise blow the deadline on any
// normal host. The exact selector is not capped: it is enumerated by
// hand in the manifest and so is self-limiting.
const maxPatternUnits = 100

// New returns a new tool instance over the manifest-supplied selector.
func New(whitelisted, patterns []string) *Tool {
	w := make([]string, len(whitelisted))
	copy(w, whitelisted)
	p := make([]string, len(patterns))
	copy(p, patterns)
	return &Tool{whitelisted: w, patterns: p}
}

// sortUnits orders rows by name so the response, and the cache key
// derived from it, are deterministic regardless of D-Bus ordering.
func sortUnits(units []dbus.UnitStatus) []dbus.UnitStatus {
	sort.Slice(units, func(i, j int) bool { return units[i].Name < units[j].Name })
	return units
}

// excludeNamed drops any pattern match that the exact selector already
// covers, keeping the two arrays disjoint. Duplicating a unit across
// both would make a consumer that reads them together double-count.
func excludeNamed(matched []dbus.UnitStatus, exact []dbus.UnitStatus) []dbus.UnitStatus {
	if len(exact) == 0 {
		return matched
	}
	named := make(map[string]bool, len(exact))
	for _, u := range exact {
		named[u.Name] = true
	}
	out := make([]dbus.UnitStatus, 0, len(matched))
	for _, u := range matched {
		if !named[u.Name] {
			out = append(out, u)
		}
	}
	return out
}

// capUnits truncates to max, returning how many were dropped.
func capUnits(units []dbus.UnitStatus, max int) ([]dbus.UnitStatus, int) {
	if len(units) <= max {
		return units, 0
	}
	return units[:max], len(units) - max
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
	if len(t.whitelisted) == 0 && len(t.patterns) == 0 {
		return Data{Units: []Unit{}, PatternUnits: []Unit{}}, nil, nil
	}

	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("dbus: %w", err)
	}
	defer conn.Close()

	var named, matched []dbus.UnitStatus
	if len(t.whitelisted) > 0 {
		named, err = conn.ListUnitsByNamesContext(ctx, t.whitelisted)
		if err != nil {
			return nil, nil, fmt.Errorf("dbus list: %w", err)
		}
	}
	if len(t.patterns) > 0 {
		// nil states = no state filter. Unlike the by-names call this
		// only sees units systemd has loaded, so a pattern cannot
		// produce a not-found row: a pattern matching nothing and a
		// unit being absent are indistinguishable here.
		matched, err = conn.ListUnitsByPatternsContext(ctx, nil, t.patterns)
		if err != nil {
			return nil, nil, fmt.Errorf("dbus list by patterns: %w", err)
		}
	}

	matched, dropped := capUnits(sortUnits(excludeNamed(matched, named)), maxPatternUnits)
	var warnings []string
	if dropped > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"systemd_units: whitelisted_unit_patterns resolved to %d units, capped at %d; narrow the patterns",
			len(matched)+dropped, maxPatternUnits))
	}

	out := Data{
		Units:        t.collect(ctx, conn, sortUnits(named)),
		PatternUnits: t.collect(ctx, conn, matched),
	}
	return out, warnings, nil
}

// collect fills in the per-unit detail both arrays share. Two D-Bus
// round trips per unit, which is what maxPatternUnits exists to bound.
func (t *Tool) collect(ctx context.Context, conn *dbus.Conn, listed []dbus.UnitStatus) []Unit {
	out := make([]Unit, 0, len(listed))
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
		out = append(out, entry)
	}
	return out
}
