package logs

import (
	"context"
	"strings"
	"testing"

	"host-health-mcp/daemon/internal/daemon/tools"
	"host-health-mcp/daemon/internal/shared/schema"
)

// TestHandleRejectsUnknownField covers L-1: a body with an extra
// field must fail with bad_argument and name the offending field in
// the message, not silently ignore it.
func TestHandleRejectsUnknownField(t *testing.T) {
	tl := &Tool{}
	body := []byte(`{"severity":"warning","gimme_secrets":true}`)
	_, _, err := tl.Handle(context.Background(), body)
	if err == nil {
		t.Fatal("Handle accepted unknown field; expected bad_argument")
	}
	var te *tools.Error
	if !errorsAs(err, &te) {
		t.Fatalf("error is not *tools.Error: %T (%v)", err, err)
	}
	if te.Code != schema.ErrCodeBadArgument {
		t.Errorf("error code = %q, want %q", te.Code, schema.ErrCodeBadArgument)
	}
	if !strings.Contains(te.Message, "gimme_secrets") {
		t.Errorf("error message %q does not name the offending field", te.Message)
	}
}

// errorsAs is a tiny indirection to avoid importing errors in every
// test file that needs to type-assert; keeps the test imports minimal.
func errorsAs(err error, target **tools.Error) bool {
	for e := err; e != nil; {
		if t, ok := e.(*tools.Error); ok {
			*target = t
			return true
		}
		type unwrapper interface{ Unwrap() error }
		if u, ok := e.(unwrapper); ok {
			e = u.Unwrap()
			continue
		}
		break
	}
	return false
}

// TestAuditArgsPopulatesDefaults covers the M-1 audit-completeness
// fix: the post-default enum triple is what the tool actually
// processes, so the audit entry must reflect those values when the
// caller sent an empty body.
func TestAuditArgsPopulatesDefaults(t *testing.T) {
	tl := &Tool{}
	args := tl.AuditArgs(nil)
	if args["severity"] != "warning" || args["window"] != "1h" || args["source"] != "journal" {
		t.Errorf("AuditArgs(nil) = %+v, want defaults", args)
	}
	args = tl.AuditArgs([]byte(`{"severity":"err","window":"24h","source":"audit"}`))
	if args["severity"] != "err" || args["window"] != "24h" || args["source"] != "audit" {
		t.Errorf("AuditArgs(explicit) = %+v", args)
	}
}

// TestEmptyRequestDefaults is the regression test for the 1.15.2
// canary finding: every MCP-routed `logs` call arrived with an
// empty body because the plugin's tool inputSchema only exposes
// `host`. Before the fix, validate() rejected the zero-value
// Request{} and the helper was never reached, so every fleet host
// returned tool_failed.
func TestEmptyRequestDefaults(t *testing.T) {
	var r Request
	r.applyDefaults()
	if r.Severity != "warning" {
		t.Errorf("Severity = %q, want warning", r.Severity)
	}
	if r.Window != "1h" {
		t.Errorf("Window = %q, want 1h", r.Window)
	}
	if r.Source != "journal" {
		t.Errorf("Source = %q, want journal", r.Source)
	}
	if err := r.validate(); err != nil {
		t.Errorf("validate() after defaults: %v", err)
	}
}

// TestPartialRequestOnlyFillsMissing confirms applyDefaults does
// not overwrite explicitly set fields. A direct-HTTP caller that
// passes one field must keep that field intact.
func TestPartialRequestOnlyFillsMissing(t *testing.T) {
	r := Request{Severity: "err"}
	r.applyDefaults()
	if r.Severity != "err" {
		t.Errorf("Severity = %q, want err (caller-supplied)", r.Severity)
	}
	if r.Window != "1h" {
		t.Errorf("Window = %q, want 1h (default)", r.Window)
	}
	if r.Source != "journal" {
		t.Errorf("Source = %q, want journal (default)", r.Source)
	}
}

// TestValidateRejectsBadEnum keeps the original enum-table
// behaviour: a non-empty but unknown value still fails validation
// after defaults.
func TestValidateRejectsBadEnum(t *testing.T) {
	cases := []Request{
		{Severity: "loud", Window: "1h", Source: "journal"},
		{Severity: "warning", Window: "forever", Source: "journal"},
		{Severity: "warning", Window: "1h", Source: "kernel"},
	}
	for _, c := range cases {
		c.applyDefaults()
		if err := c.validate(); err == nil {
			t.Errorf("validate() accepted bad request: %+v", c)
		}
	}
}
