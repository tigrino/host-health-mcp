package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"host-health-mcp/daemon/internal/daemon/audit"
	"host-health-mcp/daemon/internal/daemon/cache"
	"host-health-mcp/daemon/internal/shared/schema"
)

// recordingAuditor keeps the entries so the reject reason can be
// asserted: the operator-facing distinction between a wedged tool and
// a failed one lives in the audit log, which carries no wire contract.
type recordingAuditor struct{ entries []audit.Entry }

func (a *recordingAuditor) Log(e audit.Entry) { a.entries = append(a.entries, e) }

func errorResponse(t *testing.T, srv *Server, err error) (*httptest.ResponseRecorder, schema.ErrorEnvelope) {
	t.Helper()
	w := httptest.NewRecorder()
	r := authedRequest(http.MethodPost, "/v1/manifest", "")
	srv.handleToolError(w, r, "manifest", err, time.Now())

	var env schema.ErrorEnvelope
	if e := json.Unmarshal(w.Body.Bytes(), &env); e != nil {
		t.Fatalf("response is not an error envelope: %v (%s)", e, w.Body.String())
	}
	return w, env
}

// Positive: a tool refusing because earlier invocations have not
// returned is 503, not 502. The condition is temporary and clears when
// the wedged call returns, so a caller has to be able to tell that
// retrying later is worthwhile.
func TestAStalledToolIsServiceUnavailable(t *testing.T) {
	srv := newHandlerServer(t, nil, &recordingAuditor{})

	w, env := errorResponse(t, srv, cache.ErrStalled)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("stalled tool: got HTTP %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	if env.Error.Message != schema.MsgToolStalled {
		t.Errorf("message: got %q, want %q", env.Error.Message, schema.MsgToolStalled)
	}
}

// The error CODE stays within the published enum. Codes are the wire
// contract (schema-draft.yaml); messages are drawn from a compiled-in
// catalogue and may be added to. Inventing a code here would break
// every client that switches on it.
func TestAStalledToolKeepsAPublishedErrorCode(t *testing.T) {
	srv := newHandlerServer(t, nil, &recordingAuditor{})

	_, env := errorResponse(t, srv, cache.ErrStalled)

	published := map[string]bool{
		schema.ErrCodeAuthRequired: true, schema.ErrCodeAuthFailed: true,
		schema.ErrCodeUnknownTool: true, schema.ErrCodeToolDisabled: true,
		schema.ErrCodeBadArgument: true, schema.ErrCodeRateLimited: true,
		schema.ErrCodeToolTimeout: true, schema.ErrCodeToolFailed: true,
		schema.ErrCodeSchemaIncompatible: true, schema.ErrCodeInternalError: true,
	}
	if !published[env.Error.Code] {
		t.Fatalf("code %q is not in the published enum", env.Error.Code)
	}
	if env.Error.Code != schema.ErrCodeToolFailed {
		t.Errorf("code: got %q, want %q", env.Error.Code, schema.ErrCodeToolFailed)
	}
}

// Negative: an ordinary timeout must stay 504 with its own code. If
// stalled and timed-out collapsed onto one response, the bound would
// have removed the leak and hidden the reason.
func TestAnOrdinaryTimeoutIsStillDistinct(t *testing.T) {
	srv := newHandlerServer(t, nil, &recordingAuditor{})

	w, env := errorResponse(t, srv, context.DeadlineExceeded)

	if w.Code != http.StatusGatewayTimeout {
		t.Errorf("timeout: got HTTP %d, want %d", w.Code, http.StatusGatewayTimeout)
	}
	if env.Error.Code != schema.ErrCodeToolTimeout {
		t.Errorf("timeout code: got %q, want %q", env.Error.Code, schema.ErrCodeToolTimeout)
	}
	if env.Error.Message == schema.MsgToolStalled {
		t.Error("a timeout must not report the stalled message")
	}
}

// Negative: an unclassified failure must stay 502. The stalled branch
// must not widen into a catch-all — that would tell callers to retry
// something that will fail identically.
func TestAnUnclassifiedFailureIsStillBadGateway(t *testing.T) {
	srv := newHandlerServer(t, nil, &recordingAuditor{})

	w, env := errorResponse(t, srv, errors.New("parser blew up"))

	if w.Code != http.StatusBadGateway {
		t.Errorf("generic failure: got HTTP %d, want %d", w.Code, http.StatusBadGateway)
	}
	if env.Error.Message != schema.MsgToolFailed {
		t.Errorf("message: got %q, want %q", env.Error.Message, schema.MsgToolFailed)
	}
}

// The audit log has to name the condition. It is where an operator
// looks to distinguish a tool that is wedged from one that is merely
// erroring, and unlike the envelope it carries no compatibility
// constraint.
func TestTheAuditLogNamesAStalledTool(t *testing.T) {
	a := &recordingAuditor{}
	srv := newHandlerServer(t, nil, a)

	errorResponse(t, srv, cache.ErrStalled)

	if len(a.entries) != 1 {
		t.Fatalf("expected exactly one audit entry, got %d", len(a.entries))
	}
	if got := a.entries[0].RejectReason; got != "stalled" {
		t.Errorf("audit reject_reason: got %q, want %q", got, "stalled")
	}
	// Result carries the wire error code, so it cannot carry the
	// distinction on its own — a stalled tool and a failed one share
	// tool_failed by design.
	if got := a.entries[0].Result; got != schema.ErrCodeToolFailed {
		t.Errorf("audit result: got %q, want %q", got, schema.ErrCodeToolFailed)
	}
}

// The daemon must not leak the error's own text into the envelope.
// schema-draft.yaml forbids free-form interpolation of subsystem
// strings into messages; ErrStalled's text names internals.
func TestTheStalledEnvelopeDoesNotLeakInternalText(t *testing.T) {
	srv := newHandlerServer(t, nil, &recordingAuditor{})

	_, env := errorResponse(t, srv, cache.ErrStalled)

	if env.Error.Message == cache.ErrStalled.Error() {
		t.Error("the envelope message is the raw internal error string")
	}
}
