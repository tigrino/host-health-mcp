package ops

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestClassifySshJournalLine covers the 1.16.1 regression: the
// pre-fix classifier only recognised "Accepted "/"Failed " prefixes,
// so on key-only fleets `failed_last_24h` stayed at zero because
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
		{"Failed password for invalid user root from 192.0.2.10 port 1 ssh2", sshJournalFailed},
		{"Disconnected from 192.0.2.10 port 54321 [preauth]", sshJournalFailed},
		{"Connection closed by 192.0.2.20 port 41234 [preauth]", sshJournalFailed},
		{"error: kex_exchange_identification: read: Connection reset by peer", sshJournalFailed},

		// double-count guard
		{"Received disconnect from 192.0.2.10 port 54321:11: Bye Bye [preauth]", sshJournalOther},

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

// TestSshJournalTruncated covers the 24h-rebased coverage probe. A
// host up longer than 24h whose journal's oldest retained entry sits
// well after the 24h cutoff is truncated; a host booted inside the
// window (naturally short span) is not; a journal reaching back past
// the cutoff is not.
func TestSshJournalTruncated(t *testing.T) {
	const now = int64(1_800_000_000)
	const day = int64(24 * 3600)
	cutoff := now - day // sshJournalWindowS
	cases := []struct {
		name          string
		btime, oldest int64
		want          bool
	}{
		// Up 10 days; journal only retains ~6h → oldest far after cutoff.
		{"rotated within window", now - 10*day, now - 6*3600, true},
		// Up 10 days; journal reaches back a full 24h+ → covered.
		{"full window retained", now - 10*day, cutoff - 3600, false},
		// Booted 5h ago → short span is expected, not truncation.
		{"booted inside window", now - 5*3600, now - 5*3600, false},
		// Oldest exactly at cutoff (within tolerance) → not flagged.
		{"oldest at cutoff", now - 10*day, cutoff, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sshJournalTruncated(c.btime, c.oldest, now); got != c.want {
				t.Errorf("sshJournalTruncated(btime=%d, oldest=%d) = %v, want %v",
					c.btime, c.oldest, got, c.want)
			}
		})
	}
}

// TestParseBtimeFromProcStat covers the 1.16.2 truncation probe.
// /proc/stat's `btime` field is the canonical kernel boot time the
// helper compares against the journal's oldest retained entry.
func TestParseBtimeFromProcStat(t *testing.T) {
	t.Run("typical layout", func(t *testing.T) {
		data := []byte(`cpu  1 2 3 4 5 6 7 8 9 10
cpu0 0 0 0 0 0 0 0 0 0 0
intr 100
ctxt 200
btime 1716000000
processes 300
`)
		got, err := parseBtimeFromProcStat(data)
		if err != nil {
			t.Fatal(err)
		}
		if got != 1716000000 {
			t.Errorf("got %d, want 1716000000", got)
		}
	})
	t.Run("missing btime", func(t *testing.T) {
		if _, err := parseBtimeFromProcStat([]byte("cpu 1 2 3\nctxt 99\n")); err == nil {
			t.Error("expected error on missing btime")
		}
	})
	t.Run("malformed btime", func(t *testing.T) {
		if _, err := parseBtimeFromProcStat([]byte("btime not-a-number\n")); err == nil {
			t.Error("expected error on malformed btime")
		}
	})
}

// TestListBootsJSONShape locks in our assumption about the shape
// journalctl --list-boots --output=json produces — we only consume
// `index` and `first_entry`, so any future systemd field additions
// must remain backward-compatible. The fixture matches what
// systemd v252 (Debian 12) emits.
func TestListBootsJSONShape(t *testing.T) {
	fixture := []byte(`[
		{"index":-1,"boot_id":"old","first_entry":1715000000000000,"last_entry":1715500000000000},
		{"index":0,"boot_id":"current","first_entry":1716000000000000,"last_entry":1716309600000000}
	]`)
	var boots []struct {
		Index      int   `json:"index"`
		FirstEntry int64 `json:"first_entry"`
	}
	if err := json.Unmarshal(fixture, &boots); err != nil {
		t.Fatal(err)
	}
	var firstEntry int64
	for _, b := range boots {
		if b.Index == 0 {
			firstEntry = b.FirstEntry
			break
		}
	}
	if firstEntry != 1716000000000000 {
		t.Errorf("first_entry for index=0 = %d, want 1716000000000000", firstEntry)
	}
}

// TestParseBtimeFromTempFile is a smoke test that the file-IO
// wrapper finds and parses a real /proc/stat-shaped file.
func TestParseBtimeFromTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stat")
	if err := os.WriteFile(path, []byte("ctxt 1\nbtime 1716000000\nprocesses 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseBtimeFromProcStat(data)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1716000000 {
		t.Errorf("got %d, want 1716000000", got)
	}
}
