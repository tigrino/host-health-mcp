// Package helperinvoke is the SOLE site in the daemon source tree that
// talks to the helper service. The custom forbidden-call linter
// exempts this package only (design §7.4). The package exposes
// enum-typed Go calls; subcommand-token strings are constructed inside
// from the closed proto.Op* constants, never from caller-influenced
// values.
package helperinvoke

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"host-health-mcp/daemon/internal/shared/proto"
	"host-health-mcp/daemon/internal/shared/schema"
)

// Client dials the helper's unix socket per call. Calls do not share a
// connection: the helper is allowed to be slow on one op without
// blocking another. The Client itself is safe for concurrent use.
type Client struct {
	socketPath string

	// concurrency cap (design §7.4): bound the number of in-flight
	// helper calls so a single storm cannot overrun the helper.
	sem chan struct{}
}

// NewClient returns a Client. maxInFlight bounds the simultaneous
// helper calls; 0 disables the cap.
func NewClient(socketPath string, maxInFlight int) *Client {
	c := &Client{socketPath: socketPath}
	if maxInFlight > 0 {
		c.sem = make(chan struct{}, maxInFlight)
	}
	return c
}

// Call sends one request frame and returns the typed response Data.
// Op tokens come from proto/ops.go; param is whatever validated value
// the caller has computed. Caller cancellation propagates to the
// helper via context.
func (c *Client) Call(ctx context.Context, op string, param string) (json.RawMessage, error) {
	if !proto.IsKnownOp(op) {
		return nil, fmt.Errorf("helperinvoke: unknown op %q", op)
	}

	if c.sem != nil {
		select {
		case c.sem <- struct{}{}:
			defer func() { <-c.sem }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("helperinvoke: dial: %w", err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// Watch ctx.Done(): closing the conn from a watcher unblocks
	// any in-flight WriteFrame/ReadFrame even when the ctx is
	// cancelled without a deadline (the SetDeadline above only
	// fires when ctx carries one). Without this, a bare
	// context.Cancel() leaves the call pinned to the helper's idle
	// deadline (60 s) and leaks the goroutine until then.
	watcherDone := make(chan struct{})
	defer close(watcherDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Unix(1, 0))
		case <-watcherDone:
		}
	}()

	if err := proto.WriteFrame(conn, proto.Request{Op: op, Param: param}); err != nil {
		return nil, fmt.Errorf("helperinvoke: write: %w", err)
	}

	var resp proto.Response
	if err := proto.ReadFrameWithCap(conn, &resp, proto.MaxResponseFrame); err != nil {
		return nil, fmt.Errorf("helperinvoke: read: %w", err)
	}

	if resp.Status != proto.StatusOK {
		return nil, &HelperError{
			Code:         resp.Code,
			Message:      resp.Message,
			StderrBytes:  resp.StderrBytes,
			StderrSHA256: resp.StderrSHA256,
			StderrPrefix: resp.StderrPrefix,
			ToolExit:     resp.ToolExit,
			Argv:         resp.Argv,
		}
	}
	return resp.Data, nil
}

// HelperError is the typed error a helper call returns on Status=err.
// Argv and StderrPrefix carry actionable diagnostics for per-source
// error blocks (schema 0.2.0).
type HelperError struct {
	Code         string
	Message      string
	StderrBytes  int
	StderrSHA256 string
	StderrPrefix string
	ToolExit     *int
	Argv         []string
}

// Error returns a short, code-only summary. Argv, exit code, and
// stderr prefix are deliberately NOT included so that warning
// strings built from `err.Error()` don't leak subprocess command
// vectors or stderr bytes into the envelope. Callers that want the
// actionable diagnostics should place the structured field via
// AsOpError() into their tool's response data instead.
func (e *HelperError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("helper: %s: %s", e.Code, e.Message)
	}
	return "helper: " + e.Code
}

// AsOpError returns the wire-schema HelperOpError shape carrying the
// full structured diagnostics. Used by tools that surface a
// per-source error block in their response.
func (e *HelperError) AsOpError() *schema.HelperOpError {
	return &schema.HelperOpError{
		Code:         e.Code,
		Message:      e.Message,
		Argv:         e.Argv,
		ExitCode:     e.ToolExit,
		StderrSHA256: e.StderrSHA256,
		StderrPrefix: e.StderrPrefix,
	}
}

// OpErrorFrom converts any error into a *schema.HelperOpError. A
// *HelperError contributes its structured fields; anything else
// becomes a generic tool_failed with the error string in Message.
func OpErrorFrom(err error) *schema.HelperOpError {
	if err == nil {
		return nil
	}
	var he *HelperError
	if errors.As(err, &he) {
		return he.AsOpError()
	}
	return &schema.HelperOpError{Code: "tool_failed", Message: err.Error()}
}

// CodeOf extracts the helper error code from err, or returns
// "tool_failed" for any non-HelperError. Used by tool code that
// builds short warning strings.
func CodeOf(err error) string {
	var he *HelperError
	if errors.As(err, &he) {
		return he.Code
	}
	return "tool_failed"
}

// CallJSON wraps Call and unmarshals the result into v.
func (c *Client) CallJSON(ctx context.Context, op string, param string, v any) error {
	data, err := c.Call(ctx, op, param)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("helperinvoke: unmarshal: %w", err)
	}
	return nil
}

// ensure the type is used by linker even if no test imports it.
var _ sync.Locker = (*sync.Mutex)(nil)
