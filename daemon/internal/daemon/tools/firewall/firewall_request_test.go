package firewall

import (
	"context"
	"strings"
	"testing"

	"host-health-mcp/daemon/internal/daemon/config"
	"host-health-mcp/daemon/internal/daemon/tools"

	"host-health-mcp/daemon/internal/shared/schema"
)

// TestValidateRequestMode covers the closed mode set. Before 2.2.1 the
// only test anywhere was the helper's `mode == "detail"`, so a typo
// silently produced a summary response and the caller had no way to
// tell that the argument had not been understood.
func TestValidateRequestMode(t *testing.T) {
	accepted := []string{"", "summary", "detail"}
	for _, m := range accepted {
		if err := validateRequest(&Request{Mode: m}); err != nil {
			t.Errorf("mode %q rejected: %v", m, err.Message)
		}
	}

	rejected := []string{"detial", "Detail", "DETAIL", "summary ", " detail", "full", "0"}
	for _, m := range rejected {
		err := validateRequest(&Request{Mode: m})
		if err == nil {
			t.Errorf("mode %q accepted; expected bad_argument", m)
			continue
		}
		if err.Code != schema.ErrCodeBadArgument {
			t.Errorf("mode %q: code = %q, want %q", m, err.Code, schema.ErrCodeBadArgument)
		}
	}
}

// TestValidateRequestTable covers the table filter. The old behaviour
// failed OPEN: a value that did not split into two parts left the
// helper's filter nil, and the nil filter matched everything, so a
// malformed filter returned the entire ruleset instead of narrowing it.
func TestValidateRequestTable(t *testing.T) {
	accepted := []string{"", "inet/filter", "ip/nat", "ip6/filter", "inet/my-table"}
	for _, tbl := range accepted {
		if err := validateRequest(&Request{Table: tbl}); err != nil {
			t.Errorf("table %q rejected: %v", tbl, err.Message)
		}
	}

	rejected := []struct {
		table string
		why   string
	}{
		{"garbage", "no separator: previously returned the whole ruleset"},
		{"inet", "family only"},
		{"/filter", "empty family"},
		{"inet/", "empty name"},
		{"/", "both empty"},
	}
	for _, c := range rejected {
		err := validateRequest(&Request{Table: c.table})
		if err == nil {
			t.Errorf("table %q accepted (%s); expected bad_argument", c.table, c.why)
			continue
		}
		if err.Code != schema.ErrCodeBadArgument {
			t.Errorf("table %q: code = %q, want %q", c.table, err.Code, schema.ErrCodeBadArgument)
		}
	}
}

// TestValidateRequestTableAcceptsExtraSlashes documents that only the
// first separator is significant, matching the helper's own split, so a
// table name containing a slash still resolves.
func TestValidateRequestTableAcceptsExtraSlashes(t *testing.T) {
	if err := validateRequest(&Request{Table: "inet/a/b"}); err != nil {
		t.Errorf("table %q rejected: %v", "inet/a/b", err.Message)
	}
}

// TestValidateRequestMessagesAreActionable asserts the errors name the
// expected form rather than echoing the caller's input back, which the
// error envelope is not supposed to do.
func TestValidateRequestMessagesAreActionable(t *testing.T) {
	modeErr := validateRequest(&Request{Mode: "detial"})
	if !strings.Contains(modeErr.Message, "summary") || !strings.Contains(modeErr.Message, "detail") {
		t.Errorf("mode error does not name the valid set: %q", modeErr.Message)
	}
	if strings.Contains(modeErr.Message, "detial") {
		t.Errorf("mode error echoes caller input: %q", modeErr.Message)
	}

	tblErr := validateRequest(&Request{Table: "garbage"})
	if !strings.Contains(tblErr.Message, "family") {
		t.Errorf("table error does not name the expected form: %q", tblErr.Message)
	}
	if strings.Contains(tblErr.Message, "garbage") {
		t.Errorf("table error echoes caller input: %q", tblErr.Message)
	}
}

// TestHandleValidatesBeforeManifestCheck is the regression test for the
// 2.2.1 ordering defect: validation sat after the `!mf.Enabled` early
// return, so the same malformed request was rejected on a host with the
// tool enabled and accepted with a 200 on a host with it disabled.
// Argument validity is a property of the request, not the deployment.
//
// The disabled path returns before touching the helper client, so a nil
// client is safe here.
func TestHandleValidatesBeforeManifestCheck(t *testing.T) {
	disabled := &Tool{mf: config.Firewall{Enabled: false}}

	bad := [][]byte{
		[]byte(`{"mode":"detial"}`),
		[]byte(`{"table":"garbage"}`),
		[]byte(`{"unknown_field":1}`),
	}
	for _, body := range bad {
		_, _, err := disabled.Handle(context.Background(), body)
		if err == nil {
			t.Errorf("body %s accepted on a disabled host; expected bad_argument", body)
			continue
		}
		te, ok := err.(*tools.Error)
		if !ok {
			t.Errorf("body %s: err type %T, want *tools.Error", body, err)
			continue
		}
		if te.Code != schema.ErrCodeBadArgument {
			t.Errorf("body %s: code = %q, want %q", body, te.Code, schema.ErrCodeBadArgument)
		}
	}

	// A well-formed request on a disabled host must still take the
	// disabled path, not an error.
	data, warnings, err := disabled.Handle(context.Background(), []byte(`{"mode":"detail"}`))
	if err != nil {
		t.Fatalf("valid request on a disabled host errored: %v", err)
	}
	if data == nil {
		t.Fatal("valid request on a disabled host returned no data")
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "disabled in manifest") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the disabled-in-manifest warning, got %v", warnings)
	}
}
