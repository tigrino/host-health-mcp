package logs

import "testing"

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
