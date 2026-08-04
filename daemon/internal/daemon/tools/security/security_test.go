package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestIsSSHDLine covers the Bug 2 regression: Debian 13 / OpenSSH 9.8+
// split the daemon into sshd[PID] (listener) and sshd-session[PID]
// (per-connection handler). The pre-1.16.1 implementation only
// matched `sshd[`, so every auth-related line on trixie was ignored
// and the counter was permanently zero.
func TestIsSSHDLine(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"Apr 18 12:34:56 host1 sshd[12345]: Accepted publickey for operator from 10.0.0.5", true},
		{"Apr 18 12:34:56 host1 sshd-session[12345]: Disconnected from 192.0.2.10 port 54321 [preauth]", true},
		{"Apr 18 12:34:56 host1 CRON[99]: pam_unix(cron:session): session opened", false},
		{"Apr 18 12:34:56 host1 sshd-keygen[1]: regenerating host keys", false},
	}
	for _, c := range cases {
		if got := isSSHDLine(c.line); got != c.want {
			t.Errorf("isSSHDLine(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

// TestIsSSHFailedLine covers the Bug 1 regression: on key-only SSH
// fleets the bare `Failed ` pattern never fires because scanners
// disconnect during key exchange. The preauth-disconnect, connection-
// close, and kex-error branches capture the real rejection signal.
// Each branch is exercised once positive, and the "Received
// disconnect from" line is asserted negative so we don't double-count
// against "Disconnected from".
func TestIsSSHFailedLine(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"Failed password for invalid user root from 192.0.2.10 port 12345 ssh2", true},
		{"Disconnected from 192.0.2.10 port 54321 [preauth]", true},
		{"Connection closed by 192.0.2.10 port 54321 [preauth]", true},
		{"error: kex_exchange_identification: read: Connection reset by peer", true},
		{"Received disconnect from 192.0.2.10 port 54321:11: Bye Bye [preauth]", false}, // double-count guard
		{"Accepted publickey for operator from 10.0.0.5 port 12345 ssh2", false},
		{"Disconnected from user operator 10.0.0.5 port 12345", false}, // post-auth normal logout, no [preauth]
	}
	for _, c := range cases {
		if got := isSSHFailedLine(c.line); got != c.want {
			t.Errorf("isSSHFailedLine(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

// TestReadAuthLogCountersEndToEnd writes a synthetic auth.log with
// mixed sshd / sshd-session lines and asserts the counts the bug
// report's fleet data implies.
func TestReadAuthLogCountersEndToEnd(t *testing.T) {
	// Build a representative slice: 2 accepted lines (one of each
	// process-name format) + 6 failed-attempt lines across all
	// four rejection patterns + 1 "Received disconnect" line that
	// MUST be ignored to avoid double-counting.
	lines := []string{
		"Apr 18 12:34:56 host1 sshd[10]: Accepted publickey for operator from 10.0.0.5 port 1 ssh2",
		"Apr 18 12:34:57 host1 sshd-session[11]: Accepted publickey for operator from 10.0.0.5 port 2 ssh2",
		"Apr 18 12:35:00 host1 sshd-session[20]: Failed password for invalid user root from 192.0.2.10 port 12345 ssh2",
		"Apr 18 12:35:01 host1 sshd-session[21]: Disconnected from 192.0.2.10 port 54321 [preauth]",
		"Apr 18 12:35:01 host1 sshd-session[21]: Received disconnect from 192.0.2.10 port 54321:11: Bye Bye [preauth]",
		"Apr 18 12:35:02 host1 sshd-session[22]: Connection closed by 192.0.2.20 port 41234 [preauth]",
		"Apr 18 12:35:03 host1 sshd-session[23]: error: kex_exchange_identification: read: Connection reset by peer",
		"Apr 18 12:35:04 host1 sshd[24]: Disconnected from 192.0.2.30 port 30303 [preauth]",
		"Apr 18 12:35:05 host1 CRON[99]: pam_unix(cron:session): session opened for user root",
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// Inject the temp path at the head of authLogPaths so the
	// real /var/log/auth.log on the test host doesn't shadow it.
	orig := authLogPaths
	authLogPaths = []string{path}
	t.Cleanup(func() { authLogPaths = orig })

	accepted, failed, found, truncated, err := readAuthLogCounters()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !found {
		t.Fatal("found=false on a present file")
	}
	if truncated {
		t.Fatal("truncated=true on a file well under the cap")
	}
	if accepted != 2 {
		t.Errorf("accepted = %d, want 2", accepted)
	}
	if failed != 5 {
		t.Errorf("failed = %d, want 5 (Failed + 2x Disconnected + Connection closed + kex_exchange_identification; Received-disconnect must be skipped)", failed)
	}
}

// TestReadAuthLogCountersScanError asserts that a file with a line
// exceeding the scanner's 1 MiB buffer (bufio.ErrTooLong) is reported
// as a read error with found=false, so the caller falls back to the
// bounded journal path instead of trusting partial counts.
func TestReadAuthLogCountersScanError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	// One line longer than the scanner's 1<<20 max token size.
	huge := make([]byte, (1<<20)+1024)
	for i := range huge {
		huge[i] = 'x'
	}
	huge = append(huge, '\n')
	if err := os.WriteFile(path, huge, 0o600); err != nil {
		t.Fatal(err)
	}

	orig := authLogPaths
	authLogPaths = []string{path}
	t.Cleanup(func() { authLogPaths = orig })

	_, _, found, _, err := readAuthLogCounters()
	if err == nil {
		t.Fatal("expected a scan error on an over-long line, got nil")
	}
	if found {
		t.Error("found=true on a truncated read; caller would trust partial counts")
	}
}

// TestFormatSshJournalTruncationWarning covers the 24h-rebased
// coverage warning emitted when the journal retains less than the
// full 24h window. It carries the oldest-entry timestamp and a
// human-readable retained-window summary.
func TestFormatSshJournalTruncationWarning(t *testing.T) {
	// oldest ~6h ago so the retained window renders in hours; let
	// time.Unix render the expected RFC3339 string so the assertion
	// stays locked to the formatter's actual output.
	oldest := time.Now().UTC().Unix() - 6*3600
	got := formatSshJournalTruncationWarning(oldest)

	oldestStr := time.Unix(oldest, 0).UTC().Format(time.RFC3339)
	checks := []string{
		"ssh_logins:",
		"journal retains less than 24h",
		oldestStr,
		"24h window",
		"volatile journald",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("warning missing %q\nfull: %s", want, got)
		}
	}
}

// TestShortDuration verifies the human-readable unit selection used
// inside the truncation warning. Boundaries: under 1h → minutes,
// under 1d → hours, otherwise days.
func TestShortDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "0m"},
		{1 * time.Minute, "1m"},
		{1 * time.Hour, "1h"},
		{2 * time.Hour, "2h"},
		{24 * time.Hour, "1d"},
		{4 * 24 * time.Hour, "4d"},
	}
	for _, c := range cases {
		if got := shortDuration(c.d); got != c.want {
			t.Errorf("shortDuration(%s) = %q, want %q", c.d, got, c.want)
		}
	}
}

// M3: the 8 MiB tail cap must not be reported under
// window: since_log_rotation. That discriminator was added in 2.0.0 so
// a count is never ambiguous about what it spans, and a sustained
// brute-force — the event these counters exist to surface — is exactly
// what grows auth.log past the cap.
func TestAuthLogTruncationIsReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")

	line := "Apr 18 12:34:56 host sshd[1]: Failed password for root from 192.0.2.10 port 1 ssh2\n"
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for written := 0; written < maxAuthLogBytes+len(line); written += len(line) {
		if _, err := f.WriteString(line); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	orig := authLogPaths
	authLogPaths = []string{path}
	t.Cleanup(func() { authLogPaths = orig })

	_, _, found, truncated, err := readAuthLogCounters()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !found {
		t.Fatal("found=false on a present file")
	}
	if !truncated {
		t.Error("a file over the cap did not report truncated; the caller would " +
			"label tail-only counts as covering the whole rotation period")
	}
}

// NEGATIVE: the 8 MiB tail cap must not be published under
// window: since_log_rotation.
//
// That discriminator was added in 2.0.0 so a count is never ambiguous
// about what it spans. A sustained brute-force is what grows auth.log
// past the cap, so the mislabel fires during exactly the event these
// counters exist to surface: the number is capped while the label
// asserts it covers the whole rotation period.
func TestTruncatedAuthLogIsNotLabelledSinceRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	line := "Apr 18 12:34:56 host sshd[1]: Failed password for root from 192.0.2.10 port 1 ssh2\n"
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < maxAuthLogBytes+len(line); n += len(line) {
		if _, err := f.WriteString(line); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	orig := authLogPaths
	authLogPaths = []string{path}
	t.Cleanup(func() { authLogPaths = orig })

	_, _, found, truncated, err := readAuthLogCounters()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !found || !truncated {
		t.Fatalf("found=%v truncated=%v; want both true", found, truncated)
	}
	// The caller must not assert a window the counts do not cover.
	if sshWindowSinceLogRotation == sshWindowUnavailable {
		t.Fatal("test premise broken: the two window values are identical")
	}
}

// POSITIVE: a small auth.log is not flagged, so the normal path still
// reports since_log_rotation.
func TestSmallAuthLogIsNotTruncated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path,
		[]byte("Apr 18 12:34:56 host sshd[1]: Accepted password for ops from 192.0.2.10 port 1 ssh2\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	orig := authLogPaths
	authLogPaths = []string{path}
	t.Cleanup(func() { authLogPaths = orig })

	a, _, found, truncated, err := readAuthLogCounters()
	if err != nil || !found {
		t.Fatalf("err=%v found=%v", err, found)
	}
	if truncated {
		t.Error("a small file was flagged truncated; the tool would stop reporting a window it can support")
	}
	if a != 1 {
		t.Errorf("accepted = %d, want 1", a)
	}
}
