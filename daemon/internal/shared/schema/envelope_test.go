package schema

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// B-11: the Error.Message doc states a 200-char bound and a fixed
// catalogue. Neither held — logs, firewall and firewall_lookup build
// "tool: " + err.Error() where the strict decoder embeds the offending
// field name, so up to a full request body of caller-supplied bytes
// was echoed back against a stated invariant.
func TestBoundMessage(t *testing.T) {
	short := `logs: unknown field "foo"`
	if got := BoundMessage(short); got != short {
		t.Errorf("a short message was altered: %q", got)
	}

	long := "logs: " + strings.Repeat("x", 4096)
	got := BoundMessage(long)
	if len(got) > MaxMessageLen {
		t.Errorf("BoundMessage returned %d bytes, over the stated %d cap", len(got), MaxMessageLen)
	}
	if !strings.HasSuffix(got, "…") {
		t.Error("a truncated message must be marked as truncated")
	}

	// Caller-supplied bytes can be multi-byte; slicing mid-rune would
	// put invalid UTF-8 into a JSON string.
	multibyte := strings.Repeat("é", 4096)
	got = BoundMessage(multibyte)
	if len(got) > MaxMessageLen {
		t.Errorf("multibyte: %d bytes, over the %d cap", len(got), MaxMessageLen)
	}
	if !utf8.ValidString(got) {
		t.Error("truncation produced invalid UTF-8")
	}

	if got := BoundMessage(""); got != "" {
		t.Errorf("BoundMessage(\"\") = %q", got)
	}
}
