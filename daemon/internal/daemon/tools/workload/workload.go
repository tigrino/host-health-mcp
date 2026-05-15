package workload

import (
	"context"
	"sort"
	"time"

	"host-health-mcp/daemon/internal/daemon/helperinvoke"
)

// Data is the response data for tool workload. Mirrors the schema:
// a map keyed by plugin name to the plugin's typed sub-object.
type Data map[string]any

// Tool is the registered tool.
type Tool struct {
	hc      *helperinvoke.Client
	enabled []string // names from manifest.yml workload_plugins[]
}

// New returns a new tool instance. enabled is the manifest-declared
// plugin set; only plugins both compiled-in AND in this list are
// invoked.
func New(hc *helperinvoke.Client, enabled []string) *Tool {
	e := make([]string, len(enabled))
	copy(e, enabled)
	sort.Strings(e)
	return &Tool{hc: hc, enabled: e}
}

// Name returns the tool name.
func (*Tool) Name() string { return "workload" }

// DefaultTTL: workload state moves slowly.
func (*Tool) DefaultTTL() time.Duration { return 30 * time.Second }

// DefaultTimeout caps the per-call duration.
func (*Tool) DefaultTimeout() time.Duration { return 5 * time.Second }

// Handle invokes each enabled plugin sequentially. A failing plugin
// surfaces as an envelope warning; the rest are returned. The
// alternative - failing the whole call on one plugin's failure -
// would prevent operators from seeing the healthy workload state on
// a host where (say) one of three configured plugins has a bug.
func (t *Tool) Handle(ctx context.Context, _ []byte) (any, []string, error) {
	d := Data{}
	var warnings []string

	for _, name := range t.enabled {
		p, ok := Lookup(name)
		if !ok {
			// This should have been caught at daemon startup (REQ
			// 8.2: refuse to start if manifest references a plugin
			// not compiled in). Surface it defensively at call time
			// too.
			warnings = append(warnings, "workload: plugin not compiled in: "+name)
			continue
		}
		result, err := p.Collect(ctx, t.hc)
		if err != nil {
			warnings = append(warnings, "workload: "+name+": "+err.Error())
			continue
		}
		d[name] = result
	}
	return d, warnings, nil
}
