// Package workload implements tool 4.9: per-host workload-plugin set.
// Plugins are compile-time only and select via build tags. Loadable
// shared objects are forbidden (REQ 4.9).
package workload

import (
	"context"
	"sync"

	"host-health-mcp/daemon/internal/daemon/helperinvoke"
)

// Plugin is one compile-time workload contribution. Each plugin
// returns a typed sub-object keyed under its Name() in the response.
type Plugin interface {
	// Name returns the plugin's identifier as listed in
	// manifest.yml's workload_plugins[]. Must match the helper-side
	// op token when the plugin delegates to a helper op.
	Name() string

	// Collect produces the plugin's typed result. The helperinvoke
	// client is passed in so plugins that need privileged data can
	// reach the helper without owning their own client. cfg is the
	// plugin's slice of manifest.workload_plugin_config keyed by
	// plugin Name(); empty when the operator did not configure this
	// plugin. Plugin-level warnings (non-fatal partial-data
	// conditions) are returned in the warnings slice; the
	// orchestrator prefixes each entry and merges into the tool-
	// level warnings envelope.
	Collect(ctx context.Context, hc *helperinvoke.Client, cfg map[string]string) (data any, warnings []string, err error)
}

var (
	registryMu sync.RWMutex
	registry   = map[string]Plugin{}
)

// Register adds a Plugin to the compile-time registry. Called from an
// init() in each plugin's source file. Panics on duplicate name -
// that's a build-time bug.
func Register(p Plugin) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, ok := registry[p.Name()]; ok {
		panic("workload: duplicate plugin: " + p.Name())
	}
	registry[p.Name()] = p
}

// Lookup returns the registered plugin for name. The bool reports
// whether one is registered (i.e. compiled into this binary).
func Lookup(name string) (Plugin, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	p, ok := registry[name]
	return p, ok
}

// CompiledIn returns the names of every registered plugin. Used by
// the daemon at startup to detect manifest.yml references to plugins
// that are not compiled in (REQ 8.2 requires refusing to start in
// that case).
func CompiledIn() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	return out
}
