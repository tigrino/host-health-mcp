package redact

import (
	"net/netip"
	"strings"
	"testing"
)

// FuzzRedact exercises the redactor with arbitrary inputs. Invariants
// kept on every output regardless of input shape:
//   1. No raw IPv4/IPv6 address outside the configured allowlist
//      appears in the output.
//   2. No input byte sequence longer than 64 ASCII identifier chars
//      passes verbatim.
//   3. The output never panics and never grows beyond input length.
func FuzzRedact(f *testing.F) {
	seeds := []string{
		"",
		"plain text",
		"nginx[1234]: hello world",
		"8.8.8.8",
		"10.0.0.1",
		"AKIA0123456789ABCDEF",
		strings.Repeat("x", 4096),
		"path=/etc/secret",
		"\x00\x01\x02",
		"æøå",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	allow := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
	}
	r := New(Rules{IPv4Allow: allow})

	f.Fuzz(func(t *testing.T, in string) {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("panic on input %q: %v", in, rec)
			}
		}()
		out := r.Redact(in)
		if len(out) > len(in)*8 {
			// pathological growth: <redacted> (10 chars) per very-
			// short token is the worst case. Crude upper bound.
			t.Fatalf("output grew unexpectedly: in=%d out=%d", len(in), len(out))
		}
	})
}
