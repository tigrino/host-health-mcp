package ops

import "testing"

// TestParseFail2banJailListExtractsNames covers the happy path: the
// list reflects what `fail2ban-client status` emits.
func TestParseFail2banJailListExtractsNames(t *testing.T) {
	out := parseFail2banJailList([]byte(
		"Status\n" +
			"|- Number of jail:	2\n" +
			"`- Jail list:	sshd, recidive\n"))
	if len(out) != 2 || out[0] != "sshd" || out[1] != "recidive" {
		t.Fatalf("parsed list = %v, want [sshd recidive]", out)
	}
}

// TestJailNameRegexFiltersInvalid covers L-3: flag-like or
// shell-shaped names must not be re-passed to fail2ban-client. The
// regex is the gate; the helper drops names that fail it.
func TestJailNameRegexFiltersInvalid(t *testing.T) {
	bad := []string{
		"-h",          // flag-like
		"foo;bar",     // command separator
		"--version",   // long flag
		"foo bar",     // whitespace
		"",            // empty
		"$(reboot)",   // shell expansion
	}
	good := []string{"sshd", "recidive", "postfix-sasl", "ssh.aggressive"}
	for _, n := range bad {
		if jailNameRE.MatchString(n) {
			t.Errorf("regex accepted bad name %q", n)
		}
	}
	for _, n := range good {
		if !jailNameRE.MatchString(n) {
			t.Errorf("regex rejected good name %q", n)
		}
	}
}
