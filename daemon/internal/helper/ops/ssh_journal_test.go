package ops

import "testing"

// TestClassifySshJournalLine covers the 1.16.1 regression: the
// pre-fix classifier only recognised "Accepted "/"Failed " prefixes,
// so on key-only fleets `failed_since_boot` stayed at zero because
// scanners disconnect during key exchange and never produce a
// "Failed " message. The preauth-disconnect, connection-close, and
// kex-error branches capture the real probe-rejection signal.
//
// "Received disconnect from" must stay classified as "other" so we
// don't double-count: every client-initiated SSH_MSG_DISCONNECT
// emits both "Received disconnect from" and "Disconnected from".
func TestClassifySshJournalLine(t *testing.T) {
	cases := []struct {
		line string
		want sshJournalClass
	}{
		{"Accepted publickey for operator from 10.0.0.5 port 1 ssh2", sshJournalAccepted},
		{"Failed password for invalid user root from 1.2.3.4 port 1 ssh2", sshJournalFailed},
		{"Disconnected from 1.2.3.4 port 54321 [preauth]", sshJournalFailed},
		{"Connection closed by 5.6.7.8 port 41234 [preauth]", sshJournalFailed},
		{"error: kex_exchange_identification: read: Connection reset by peer", sshJournalFailed},

		// double-count guard
		{"Received disconnect from 1.2.3.4 port 54321:11: Bye Bye [preauth]", sshJournalOther},

		// normal post-auth logout — no [preauth] suffix, must not count
		{"Disconnected from user operator 10.0.0.5 port 12345", sshJournalOther},

		// noise
		{"pam_unix(sshd:session): session opened for user operator(uid=1000) by (uid=0)", sshJournalOther},
		{"", sshJournalOther},
	}
	for _, c := range cases {
		got := classifySshJournalLine([]byte(c.line))
		if got != c.want {
			t.Errorf("classifySshJournalLine(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}
