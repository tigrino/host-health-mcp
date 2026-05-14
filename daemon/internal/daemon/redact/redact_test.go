package redact

import (
	"net/netip"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return p
}

func TestRedactIdentifiers(t *testing.T) {
	f := New(Rules{})
	cases := map[string]string{
		"":                          "",
		"nginx":                     "nginx",
		"sshd@123-456.service":      "sshd@123-456.service",
		"AAAAA":                     "AAAAA",
		"this is bare text":         "this is bare text",
		"abcde fghij klmno":         "abcde fghij klmno",
	}
	for in, want := range cases {
		got := f.Redact(in)
		if got != want {
			t.Errorf("Redact(%q) = %q want %q", in, got, want)
		}
	}
}

func TestRedactSuppressesUnknown(t *testing.T) {
	f := New(Rules{})
	// Tokens starting with non-letter, embedded special chars, or
	// too-long opaque strings should be replaced.
	cases := map[string]string{
		"!@#$%^":                                        "<redacted>",
		"AKIA0123456789ABCDEF":                          "AKIA0123456789ABCDEF",                // ASCII id within 64 chars passes
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA": "<redacted>", // >64 char token fails safe pattern
	}
	for in, want := range cases {
		got := f.Redact(in)
		if got != want {
			t.Errorf("Redact(%q) = %q want %q", in, got, want)
		}
	}
}

func TestRedactIPv4Allowlist(t *testing.T) {
	f := New(Rules{
		IPv4Allow: []netip.Prefix{mustPrefix(t, "10.0.0.0/8"), mustPrefix(t, "127.0.0.1/32")},
	})
	if got := f.Redact("10.5.1.2"); got != "10.5.1.2" {
		t.Errorf("IPv4 in allowlist redacted: %q", got)
	}
	if got := f.Redact("127.0.0.1"); got != "127.0.0.1" {
		t.Errorf("loopback redacted: %q", got)
	}
	if got := f.Redact("8.8.8.8"); got != "<redacted>" {
		t.Errorf("IPv4 outside allowlist passed: %q", got)
	}
}

func TestRedactIPv6Allowlist(t *testing.T) {
	f := New(Rules{
		IPv6Allow: []netip.Prefix{mustPrefix(t, "fc00::/7")},
	})
	if got := f.Redact("fd12::1"); got != "fd12::1" {
		t.Errorf("ULA in allowlist redacted: %q", got)
	}
	if got := f.Redact("2001:db8::1"); got != "<redacted>" {
		t.Errorf("documentation prefix passed: %q", got)
	}
}
