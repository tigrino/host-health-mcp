package ops

import "testing"

func TestParseDoveadmWho_Empty(t *testing.T) {
	if got := parseDoveadmWho([]byte("")); got != 0 {
		t.Fatalf("empty: got %d want 0", got)
	}
	if got := parseDoveadmWho([]byte("\n\n")); got != 0 {
		t.Fatalf("blank-only: got %d want 0", got)
	}
}

func TestParseDoveadmWho_ThreeSessions(t *testing.T) {
	in := []byte("alice  1 imap (127.0.0.1)\n" +
		"bob    2 pop3 (127.0.0.1)\n" +
		"carol  1 imap (10.0.0.1)\n")
	if got := parseDoveadmWho(in); got != 3 {
		t.Fatalf("three sessions: got %d want 3", got)
	}
}

func TestParseDoveadmWho_WithHeader(t *testing.T) {
	// Real doveadm who -1 header carries "username" and "#" as the
	// first two tokens.
	in := []byte("username  #  proto (pids) (ips)\n" +
		"alice  1 imap (127.0.0.1)\n" +
		"bob    2 pop3 (127.0.0.1)\n")
	if got := parseDoveadmWho(in); got != 2 {
		t.Fatalf("with header: got %d want 2", got)
	}
}

// A user literally named "username" produces a session line whose
// first token matches the header's first token. The tightened header
// detection must NOT treat such a line as a header, because the
// second column on a session line is a numeric session count, not
// the literal "#" the header carries.
func TestParseDoveadmWho_UserNamedUsername(t *testing.T) {
	in := []byte("username  1 imap (127.0.0.1)\n" +
		"alice  2 imap (127.0.0.1)\n")
	if got := parseDoveadmWho(in); got != 2 {
		t.Fatalf("user named username: got %d want 2", got)
	}
}

func TestParseDoveadmWho_TrailingBlankLine(t *testing.T) {
	in := []byte("alice  1 imap (127.0.0.1)\n\n")
	if got := parseDoveadmWho(in); got != 1 {
		t.Fatalf("trailing blank: got %d want 1", got)
	}
}
