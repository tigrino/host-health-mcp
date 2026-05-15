// Package dispatch routes incoming op frames to compile-time registered
// handlers. Adding a new op means registering it here; there is no
// runtime registration path.
package dispatch

import (
	"context"
	"fmt"
	"sync"

	"tigr.net/host-health-mcp/daemon/internal/shared/proto"
)

// Handler runs one helper op. Implementations validate the parameter,
// invoke the underlying read or subprocess, parse the output, and
// return the typed result. Returning a non-nil error becomes an
// `err` Response with Code set; a successful return marshals result
// into the response Data field.
type Handler func(ctx context.Context, param string) (result any, err error)

// Error is the typed error a Handler may return to convey the helper-
// side error code in proto/codes.go.
//
// Argv and StderrPrefix were added in schema 0.2.0 so the daemon's
// per-source error blocks can carry actionable diagnostics back to
// the operator. Argv is the full subprocess command vector
// (deterministic and operator-validated where the param is operator-
// supplied — smart device names, btrfs mountpoints, systemd unit
// names). StderrPrefix is the leading 200 chars of subprocess
// stderr after byte-level control-char sanitisation. Raw stderr is
// still kept inside the helper; only the bounded, sanitised prefix
// crosses the socket.
type Error struct {
	Code         string
	Message      string
	StderrBytes  int
	StderrSHA256 string
	StderrPrefix string
	ToolExit     *int
	Argv         []string
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return e.Code
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{handlers: make(map[string]Handler)}
}

// Registry is a compile-time-populated table of op handlers. After
// Register has been called for every op the helper supports, the
// registry is read-only for the lifetime of the process.
type Registry struct {
	mu       sync.RWMutex
	handlers map[string]Handler
}

// Register associates a Handler with an op token. It panics if the op
// token is not one of proto.AllOps or if the same token is registered
// twice; both indicate a build-time bug.
func (r *Registry) Register(op string, h Handler) {
	if !proto.IsKnownOp(op) {
		panic("dispatch: register: unknown op token " + op)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.handlers[op]; ok {
		panic("dispatch: register: duplicate op token " + op)
	}
	r.handlers[op] = h
}

// Lookup returns the registered handler for op or nil. The bool reports
// whether a handler is registered.
func (r *Registry) Lookup(op string) (Handler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.handlers[op]
	return h, ok
}

// Ops returns the set of registered op tokens in proto.AllOps order.
func (r *Registry) Ops() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.handlers))
	for _, op := range proto.AllOps {
		if _, ok := r.handlers[op]; ok {
			out = append(out, op)
		}
	}
	return out
}
