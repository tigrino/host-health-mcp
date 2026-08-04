package redact

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRules(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "redaction.yml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// B-10: log_redaction_rules was parsed, documented, shipped in the
// example config and read by nothing. An operator writing custom rules
// got a silent no-op — precisely the compensating control they would
// reach for to scrub something the positive list keeps by design.
func TestLoadRuleFileAppliesOperatorPatterns(t *testing.T) {
	path := writeRules(t, "scrub_patterns:\n  - '^[^@[:space:]]+@[^@[:space:]]+$'\n")
	pats, err := LoadRuleFile(path)
	if err != nil {
		t.Fatalf("LoadRuleFile: %v", err)
	}
	if len(pats) != 1 {
		t.Fatalf("got %d patterns, want 1", len(pats))
	}

	// Without the rule the redactor keeps an email: safeToken is
	// written to preserve them, which is what B-3 documents.
	plain := New(Rules{})
	if got := plain.Redact("user@example.com"); got != "user@example.com" {
		t.Fatalf("baseline changed: %q", got)
	}
	// With it, the same token is scrubbed.
	withRules := New(Rules{ScrubPatterns: pats})
	if got := withRules.Redact("user@example.com"); got == "user@example.com" {
		t.Error("operator pattern did not scrub the token")
	}
	// Unrelated tokens are untouched.
	if got := withRules.Redact("nginx"); got != "nginx" {
		t.Errorf("Redact(nginx) = %q, want it kept", got)
	}
}

// Operator patterns must beat every built-in exemption, including the
// UUID one — an exemption that could override them would defeat the
// purpose of an operator-supplied deny rule.
func TestOperatorPatternsBeatTheUUIDExemption(t *testing.T) {
	const uuid = "550e8400-e29b-41d4-a716-446655440000"
	if got := New(Rules{}).Redact(uuid); got != uuid {
		t.Fatalf("baseline: UUID should be exempt, got %q", got)
	}
	pats, err := LoadRuleFile(writeRules(t, "scrub_patterns:\n  - '^[0-9a-f-]{36}$'\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := New(Rules{ScrubPatterns: pats}).Redact(uuid); got == uuid {
		t.Error("operator pattern was overridden by the UUID exemption")
	}
}

// A rules file that does not parse, or that names a regexp that does
// not compile, is fatal. Redaction failing open quietly is the thing
// this package exists to prevent.
func TestLoadRuleFileFailsClosed(t *testing.T) {
	if _, err := LoadRuleFile(writeRules(t, "scrub_patterns:\n  - '[unclosed'\n")); err == nil {
		t.Error("an uncompilable regexp was accepted")
	}
	if _, err := LoadRuleFile(writeRules(t, "unknown_key: 1\n")); err == nil {
		t.Error("an unknown key was accepted")
	}
	// A missing file is reported but is NOT in the same class — see
	// TestLoadRuleFileMissingIsDistinguishable.
	if _, err := LoadRuleFile(filepath.Join(t.TempDir(), "absent.yml")); err == nil {
		t.Error("a configured-but-missing file was silently ignored")
	}
}

// The key is optional: an empty path is not an error.
func TestLoadRuleFileEmptyPathIsNotAnError(t *testing.T) {
	pats, err := LoadRuleFile("")
	if err != nil || pats != nil {
		t.Errorf("LoadRuleFile(\"\") = %v, %v; want nil, nil", pats, err)
	}
	if pats, err := LoadRuleFile("   "); err != nil || pats != nil {
		t.Errorf("LoadRuleFile(blank) = %v, %v; want nil, nil", pats, err)
	}
}

// An empty scrub_patterns list is valid and changes nothing.
func TestLoadRuleFileEmptyList(t *testing.T) {
	pats, err := LoadRuleFile(writeRules(t, "scrub_patterns: []\n"))
	if err != nil {
		t.Fatalf("LoadRuleFile: %v", err)
	}
	if len(pats) != 0 {
		t.Errorf("got %d patterns, want 0", len(pats))
	}
}

// The IP branch returns early for anything ParseAddr accepts, so with
// the operator loop placed after it, "scrub one host inside an
// otherwise allowlisted range" was silently ignored — the second most
// obvious use of this knob after email, and exactly the silent no-op
// B-10 exists to remove.
func TestOperatorPatternsBeatTheIPAllowlist(t *testing.T) {
	allow := netip.MustParsePrefix("10.0.0.0/8")

	plain := New(Rules{IPv4Allow: []netip.Prefix{allow}})
	if got := plain.Redact("10.0.0.5"); got != "10.0.0.5" {
		t.Fatalf("baseline: allowlisted IP should be kept, got %q", got)
	}

	pats, err := LoadRuleFile(writeRules(t, "scrub_patterns:\n  - '^10\\.0\\.0\\.5$'\n"))
	if err != nil {
		t.Fatal(err)
	}
	f := New(Rules{IPv4Allow: []netip.Prefix{allow}, ScrubPatterns: pats})
	if got := f.Redact("10.0.0.5"); got == "10.0.0.5" {
		t.Error("operator pattern was overridden by the IP allowlist")
	}
	// Other addresses in the range are unaffected.
	if got := f.Redact("10.0.0.6"); got != "10.0.0.6" {
		t.Errorf("Redact(10.0.0.6) = %q, want it kept", got)
	}
}

// C1: the shipped daemon.yml named a redaction file that nothing
// installs. Treating a missing file as fatal would have stopped every
// deployment that copied the example — on upgrade as well as on fresh
// install. Absent is a warning the caller handles; broken is fatal.
func TestLoadRuleFileMissingIsDistinguishable(t *testing.T) {
	_, err := LoadRuleFile(filepath.Join(t.TempDir(), "absent.yml"))
	if err == nil {
		t.Fatal("a missing file should be reported, not silently ignored")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v; the caller must be able to tell 'absent' from 'broken' "+
			"with errors.Is(err, os.ErrNotExist)", err)
	}
	// A broken file must NOT be mistakable for a missing one.
	_, err = LoadRuleFile(writeRules(t, "scrub_patterns:\n  - '[unclosed'\n"))
	if err == nil || errors.Is(err, os.ErrNotExist) {
		t.Errorf("a broken file must be fatal and distinct from absent, got %v", err)
	}
}

// An empty pattern matches every token and would turn all redacted
// output into the placeholder — fail-closed, but silently, and almost
// certainly a stray list entry.
func TestLoadRuleFileRejectsEmptyPattern(t *testing.T) {
	for _, body := range []string{
		"scrub_patterns:\n  - ''\n",
		"scrub_patterns:\n  - '   '\n",
	} {
		if _, err := LoadRuleFile(writeRules(t, body)); err == nil {
			t.Errorf("empty pattern accepted; it would match every token (%q)", body)
		}
	}
}

// The file is read once at startup, but every pattern is walked for
// every token on the logs hot path, so the count is a per-token
// multiplier.
func TestLoadRuleFileRejectsAnOversizedFile(t *testing.T) {
	var b strings.Builder
	b.WriteString("scrub_patterns:\n")
	for b.Len() <= MaxRuleFileBytes {
		b.WriteString("  - '^averyveryverylongpatternnamethatpadsthefile[0-9]+$'\n")
	}
	if _, err := LoadRuleFile(writeRules(t, b.String())); err == nil {
		t.Error("an oversized rules file was accepted")
	}
}
