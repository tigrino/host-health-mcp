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
		"":                       "",
		"nginx":                  "nginx",
		"sshd@123-456.service":   "sshd@123-456.service",
		"AAAAA":                  "AAAAA",
		"this is bare text":      "this is bare text",
		"abcde fghij klmno":      "abcde fghij klmno",
		"albert@tigr.net":        "albert@tigr.net",
		"operator":                   "operator",
		"host-health-mcp":        "host-health-mcp",
		"12345678-1234-1234-1234-123456789abc": "12345678-1234-1234-1234-123456789abc",
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
	cases := map[string]string{
		"!@#$%^": "<redacted>",
		// AWS access key IDs must now scrub (H-2).
		"AKIA0123456789ABCDEF": "<redacted>",
		"ASIA0123456789ABCDEF": "<redacted>",
		// JWT triple.
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c": "<redacted>",
		// 33+ char base64-style blob without '@' or '.'.
		"dGhpcyBpcyBhIHRlc3Qgc3RyaW5nIGZvciByZWRhY3Q": "<redacted>",
		// >64 char token fails safe pattern.
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA": "<redacted>",
	}
	for in, want := range cases {
		got := f.Redact(in)
		if got != want {
			t.Errorf("Redact(%q) = %q want %q", in, got, want)
		}
	}
}

func TestRedactSensitiveDirs(t *testing.T) {
	f := New(Rules{SensitiveDirs: []string{"/etc/host-health-mcp/secrets", "/var/lib/foo"}})
	cases := map[string]string{
		"/etc/host-health-mcp/secrets/key.pem": "<redacted>",
		"/var/lib/foo/db":                      "<redacted>",
		"path=/etc/host-health-mcp/secrets/x":  "<redacted>",
		"/etc/hosts":                           "<redacted>", // not in safe-token allow, has '.'
		"/usr/bin/nginx":                       "<redacted>", // path token outside whitelist
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
	if got := f.Redact("192.168.1.1"); got != "<redacted>" {
		t.Errorf("IPv4 outside allowlist passed: %q", got)
	}
}

func TestRedactIPv4AllowlistWithPrivateRange(t *testing.T) {
	f := New(Rules{
		IPv4Allow: []netip.Prefix{mustPrefix(t, "192.168.0.0/16")},
	})
	if got := f.Redact("192.168.1.1"); got != "192.168.1.1" {
		t.Errorf("IPv4 in allowlist redacted: %q", got)
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
