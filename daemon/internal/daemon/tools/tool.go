// Package tools holds the daemon's per-tool implementations. Each tool
// lives in its own sub-package and registers itself in this package's
// init-time registry. The HTTP server routes /v1/<name> by looking
// up Name() in the registry.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Tool is the contract each tool implements.
type Tool interface {
	Name() string
	DefaultTTL() time.Duration
	DefaultTimeout() time.Duration
	Handle(ctx context.Context, reqBody []byte) (data any, warnings []string, err error)
}

// Registry is the compile-time-populated table of tools.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]Tool
}

// New returns an empty Registry.
func New() *Registry { return &Registry{tools: make(map[string]Tool)} }

// Register adds a tool. Panics on duplicate name (build-time bug).
func (r *Registry) Register(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.tools[t.Name()]; ok {
		panic("tools: duplicate registration for " + t.Name())
	}
	r.tools[t.Name()] = t
}

// Lookup returns the tool registered under name.
func (r *Registry) Lookup(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

// Names returns all registered tool names. Order is unspecified.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.tools))
	for n := range r.tools {
		out = append(out, n)
	}
	return out
}

// Error is the typed error a tool may return to surface a structured
// failure code. Maps to schema.ErrCode* in the HTTP response.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("tool: %s: %s", e.Code, e.Message)
}

// MarshalJSON helps tools build their data block from typed structs.
// This is a thin wrapper; tools can use the stdlib directly. Keeping
// it here documents the convention.
func MarshalJSON(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}
