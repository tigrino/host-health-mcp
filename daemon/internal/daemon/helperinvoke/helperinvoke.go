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

	"host-health-mcp/daemon/internal/daemon/redact"
	"host-health-mcp/daemon/internal/shared/proto"
	"host-health-mcp/daemon/internal/shared/schema"
)

// HelperDeadlineBudget is the slack the daemon leaves between its
// own per-tool timeout (ctx.Deadline) and the deadline applied to
// the helper socket. The helper's subprocess kill chain is
// SIGTERM->KillGrace->SIGKILL (KillGrace = 500ms in helper/exec);
// the budget here matches so the helper reply can be drained
// before the outer ctx fires.
const HelperDeadlineBudget = 500 * time.Millisecond

// Client dials the helper's unix socket per call. Calls do not share a
// connection: the helper is allowed to be slow on one op without
// blocking another. The Client itself is safe for concurrent use.
type Client struct {
	socketPath string

	// concurrency cap (design §7.4): bound the number of in-flight
	// helper calls so a single storm cannot overrun the helper.
	sem chan struct{}

	// redactor applied to forwarded subprocess stderr_prefix before it
	// leaves the daemon. The helper does not know the operator's
	// allowlists; redaction is a daemon-side concern by REQ 6.3. May be
	// nil only in unit tests that never surface a helper error.
	redactor *redact.Filter
}

// NewClient returns a Client. maxInFlight bounds the simultaneous
// helper calls; 0 disables the cap. redactor processes the subprocess
// stderr_prefix field of any HelperOpError before it leaves the daemon
// (threat-model §6.7, design §7.2).
func NewClient(socketPath string, maxInFlight int, redactor *redact.Filter) *Client {
	c := &Client{socketPath: socketPath, redactor: redactor}
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

	// Apply a helper-side deadline that's HelperDeadlineBudget
	// earlier than the daemon's outer per-tool timeout. The design
	// (§7.2) calls for the helper to have room to escalate from
	// SIGTERM to SIGKILL on its subprocess (KillGrace = 500ms)
	// without the daemon's own timeout firing first and racing the
	// helper's reply. Without this subtraction both timers fired
	// simultaneously and the helper's tail responses could lose
	// the race.
	// deadlineMS travels in the request frame so the helper can bound
	// its own handler and its subprocess to the same budget. A socket
	// deadline only unblocks THIS side: the helper goroutine sits in
	// its handler, not in a read, and notices nothing when the daemon
	// hangs up.
	deadlineMS := 0
	if deadline, ok := ctx.Deadline(); ok {
		helperDL := deadline.Add(-HelperDeadlineBudget)
		if !helperDL.After(time.Now()) {
			// Budget already consumed by the time we got here; let
			// the daemon's ctx-done watcher (below) handle it.
			helperDL = deadline
		}
		_ = conn.SetDeadline(helperDL)
		// Round UP. Milliseconds() truncates, so a sub-millisecond
		// remainder would yield 0 — which the helper reads as "no
		// budget supplied, use your configured deadline", i.e. 9.5 s
		// starting after the daemon has already given up. The one
		// input path that could silently discard the budget instead of
		// propagating it.
		if ns := time.Until(helperDL).Nanoseconds(); ns > 0 {
			deadlineMS = int((ns + int64(time.Millisecond) - 1) / int64(time.Millisecond))
		} else {
			deadlineMS = 1
		}
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

	if err := proto.WriteFrame(conn, proto.Request{Op: op, Param: param, DeadlineMS: deadlineMS}); err != nil {
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
			redactor:     c.redactor,
		}
	}
	return resp.Data, nil
}

// HelperError is the typed error a helper call returns on Status=err.
// Argv and StderrPrefix carry actionable diagnostics for per-source
// error blocks (schema 0.2.0). StderrPrefix is sanitised inside the
// helper and routed through the daemon-side positive-list redactor
// (threat-model §6.7) at AsOpError() time before it leaves the daemon.
type HelperError struct {
	Code         string
	Message      string
	StderrBytes  int
	StderrSHA256 string
	StderrPrefix string
	ToolExit     *int
	Argv         []string

	// redactor is the daemon-configured positive-list filter. Captured
	// from the originating Client; nil-safe (an unconfigured client
	// leaves the prefix unredacted, matching pre-1.17 behaviour for
	// test-only call sites).
	redactor *redact.Filter
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
// per-source error block in their response. The subprocess
// stderr_prefix passes through the daemon-side redactor so any
// content not on the positive-list collapses to <redacted> before it
// crosses the daemon's outbound boundary (REQ 6.3, threat-model §6.7).
func (e *HelperError) AsOpError() *schema.HelperOpError {
	prefix := e.StderrPrefix
	msg := e.Message
	if e.redactor != nil {
		prefix = e.redactor.Redact(prefix)
		// Message travels the same path to the same client and was
		// going out untouched. It is not a fixed catalogue string:
		// OpErrorFrom's fallback stuffs a raw err.Error() into it, and
		// a *os.PathError renders as "open /etc/host-health-mcp/...:
		// permission denied" — an absolute host path reaching the
		// caller through the one field the redactor never saw.
		// threat-model R5 covers argv disclosure; this closes the same
		// hole one field over.
		msg = e.redactor.Redact(msg)
	}
	return &schema.HelperOpError{
		Code:         e.Code,
		Message:      schema.BoundMessage(msg),
		Argv:         e.Argv,
		ExitCode:     e.ToolExit,
		StderrSHA256: e.StderrSHA256,
		StderrPrefix: prefix,
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
	return &schema.HelperOpError{Code: "tool_failed", Message: schema.BoundMessage(err.Error())}
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
