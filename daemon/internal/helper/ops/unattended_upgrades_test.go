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
			if got := parseUnattendedFromAptConfig([]byte(tc.in)); got != tc.want {
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
