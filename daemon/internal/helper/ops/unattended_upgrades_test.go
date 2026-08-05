package ops

import (
	"strings"
	"testing"
)

func TestParseUnattendedFromAptConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want bool
	}{
		{"enabled", `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";`, true},
		{"disabled", `APT::Periodic::Unattended-Upgrade "0";`, false},
		{"missing", `APT::Periodic::Update-Package-Lists "1";`, false},
		{"override-wins", `APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Unattended-Upgrade "0";`, false},
		{"override-wins-to-enabled", `APT::Periodic::Unattended-Upgrade "0";
APT::Periodic::Unattended-Upgrade "1";`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseUnattendedFromAptConfig([]byte(tc.in))
			if err != nil {
				t.Fatalf("unexpected error on well-formed input: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestParseUnattendedLastExitCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want *int
	}{
		{"success", "2026-05-15 03:00:01,123 INFO All upgrades installed\n", intPtr(0)},
		{"no-pkgs", "INFO No packages found that can be upgraded unattended and no pending auto-removals\n", intPtr(0)},
		{"failure", "2026-05-15 03:00:42,000 ERROR Upgrade failed: dpkg returned non-zero\n", intPtr(1)},
		{"failure-then-success", "Upgrade failed: foo\nAll upgrades installed\n", intPtr(0)},
		{"no-status", "Starting unattended upgrades script\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseUnattendedLastExitCode(strings.NewReader(tc.in))
			switch {
			case got == nil && tc.want == nil:
			case got == nil || tc.want == nil:
				t.Errorf("got %v want %v", got, tc.want)
			case *got != *tc.want:
				t.Errorf("got %d want %d", *got, *tc.want)
			}
		})
	}
}

func intPtr(v int) *int { return &v }

// A read that did not finish must not be reported as "unattended-
// upgrades is off". That is a security-posture claim in the unsafe
// direction, and it is indistinguishable from a host where the
// operator genuinely disabled it. The wire field is a required
// non-nullable boolean, so the only way to say "unknown" is to fail
// the op and let the reason reach errors[].
func TestATruncatedAptConfigReadFailsRatherThanReportingDisabled(t *testing.T) {
	// One line longer than the 1 MiB scanner cap, carrying the
	// enabled marker, so a parser that ignored the error would also
	// be returning the wrong value and not merely a defaulted one.
	long := strings.Repeat("x", 1<<20+1)
	in := `APT::Periodic::Unattended-Upgrade "1";` + "\n" + long + "\n"

	got, err := parseUnattendedFromAptConfig([]byte(in))

	if err == nil {
		t.Fatalf("truncated read reported enabled=%v with no error; a failed "+
			"read must not produce a posture claim", got)
	}
	if got {
		t.Error("the value returned alongside an error must not be relied on")
	}
}

// Negative: well-formed input near but under the cap must still parse.
// A bound that trips on legitimate input would fail every host.
func TestALongButValidAptConfigStillParses(t *testing.T) {
	padding := strings.Repeat("# comment\n", 1000)
	in := padding + `APT::Periodic::Unattended-Upgrade "1";` + "\n"

	got, err := parseUnattendedFromAptConfig([]byte(in))

	if err != nil {
		t.Fatalf("valid input failed to parse: %v", err)
	}
	if !got {
		t.Error("expected enabled=true")
	}
}
