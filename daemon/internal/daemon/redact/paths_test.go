package redact

import "testing"

// B-12: an error string built from a *os.PathError or a socket error
// carries an absolute host path into a field that never passed through
// any filter. The fix must remove the path WITHOUT removing the
// diagnostic — an earlier attempt ran the positive-list filter here
// and turned "stdout exceeded 1048576 bytes" into "stdout exceeded
// <redacted> bytes", which is worse than useless to an operator.
func TestPaths(t *testing.T) {
	cases := map[string]string{
		// Paths go.
		"open /etc/host-health-mcp/tls/key.pem: permission denied": "open <path>: permission denied",
		"/usr/sbin/smartctl: not found":                            "<path>: not found",
		"dial unix /run/host-health-mcp/helper.sock: refused":      "dial unix <path>: refused",

		// Diagnostics stay. These are the tokens the previous approach ate.
		"stdout exceeded 1048576 bytes":                     "stdout exceeded 1048576 bytes",
		"wg dump: row has unexpected column count 9":        "wg dump: row has unexpected column count 9",
		"smartctl JSON parse: unexpected end of JSON input": "smartctl JSON parse: unexpected end of JSON input",
		"deadline exceeded":                                 "deadline exceeded",
		"":                                                  "",
	}
	for in, want := range cases {
		if got := Paths(in); got != want {
			t.Errorf("Paths(%q)\n  got  %q\n  want %q", in, got, want)
		}
	}
}

// A path anywhere in the string must go, not only at the start.
func TestPathsScrubsEveryOccurrence(t *testing.T) {
	got := Paths("copy /etc/a.pem to /var/lib/b.pem failed")
	if want := "copy <path> to <path> failed"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// A bare slash or a relative path is not a host-layout disclosure and
// must not be mangled into noise.
func TestPathsLeavesNonPathsAlone(t *testing.T) {
	for _, s := range []string{"a/b", "24/7 polling", "n=1/2"} {
		if got := Paths(s); got != s {
			t.Errorf("Paths(%q) = %q, want it unchanged", s, got)
		}
	}
}
