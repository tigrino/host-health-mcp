// Package manifest implements tool 4.11: daemon self-description. The
// plugin calls this on first contact per session to negotiate schema
// version (REQ 7.2). Always available; never gated by the manifest.
package manifest

import (
	"context"
	"time"

	"host-health-mcp/daemon/internal/shared/schema"
)

// Data is the response data for tool manifest. Mirrors ManifestData in
// doc/schema-draft.yaml.
type Data struct {
	SchemaVersion           string    `json:"schema_version"`
	DaemonVersion           string    `json:"daemon_version"`
	BuildID                 string    `json:"build_id"`
	StartedAtTS             time.Time `json:"started_at_ts"`
	EnabledTools            []string  `json:"enabled_tools"`
	EnabledWorkloadPlugins  []string  `json:"enabled_workload_plugins"`
	WhitelistedUnits        []string  `json:"whitelisted_units"`
	WhitelistedUnitPatterns []string  `json:"whitelisted_unit_patterns"`
}

// Snapshot captures the daemon-wide values the tool returns.
type Snapshot struct {
	DaemonVersion           string
	BuildID                 string
	StartedAt               time.Time
	EnabledTools            []string
	EnabledWorkloadPlugins  []string
	WhitelistedUnits        []string
	WhitelistedUnitPatterns []string
}

// Tool is the registered tool.
type Tool struct {
	snap Snapshot
}

// New returns a manifest tool over snap. The fields in snap are
// captured by the daemon at startup; the snapshot is read-only for the
// lifetime of the process.
func New(snap Snapshot) *Tool {
	if snap.EnabledTools == nil {
		snap.EnabledTools = []string{}
	}
	if snap.EnabledWorkloadPlugins == nil {
		snap.EnabledWorkloadPlugins = []string{}
	}
	if snap.WhitelistedUnits == nil {
		snap.WhitelistedUnits = []string{}
	}
	if snap.WhitelistedUnitPatterns == nil {
		snap.WhitelistedUnitPatterns = []string{}
	}
	return &Tool{snap: snap}
}

// Name returns the tool name.
func (*Tool) Name() string { return "manifest" }

// DefaultTTL keeps the manifest answer cached for a minute; nothing in
// it changes after daemon start.
func (*Tool) DefaultTTL() time.Duration { return 60 * time.Second }

// DefaultTimeout caps the per-call duration.
func (*Tool) DefaultTimeout() time.Duration { return 1 * time.Second }

// Handle returns the snapshot.
func (t *Tool) Handle(ctx context.Context, _ []byte) (any, []string, error) {
	return Data{
		SchemaVersion:           schema.SchemaVersion,
		DaemonVersion:           t.snap.DaemonVersion,
		BuildID:                 t.snap.BuildID,
		StartedAtTS:             t.snap.StartedAt,
		EnabledTools:            t.snap.EnabledTools,
		EnabledWorkloadPlugins:  t.snap.EnabledWorkloadPlugins,
		WhitelistedUnits:        t.snap.WhitelistedUnits,
		WhitelistedUnitPatterns: t.snap.WhitelistedUnitPatterns,
	}, nil, nil
}
