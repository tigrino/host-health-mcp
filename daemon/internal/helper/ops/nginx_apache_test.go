package ops

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDetectServer_Nginx(t *testing.T) {
	root := t.TempDir()
	mustWriteComm(t, root, "100", "nginx")
	mustWriteComm(t, root, "101", "nginx")
	mustWriteComm(t, root, "102", "nginx")
	mustWriteComm(t, root, "200", "bash")
	server, n, a := detectServer(root)
	if server != "nginx" {
		t.Fatalf("server = %q want nginx", server)
	}
	if n != 3 {
		t.Fatalf("nginx count = %d want 3", n)
	}
	if a != 0 {
		t.Fatalf("apache count = %d want 0", a)
	}
}

func TestDetectServer_Apache(t *testing.T) {
	root := t.TempDir()
	mustWriteComm(t, root, "300", "apache2")
	mustWriteComm(t, root, "301", "apache2")
	mustWriteComm(t, root, "302", "apache2")
	mustWriteComm(t, root, "303", "apache2")
	server, _, a := detectServer(root)
	if server != "apache" {
		t.Fatalf("server = %q want apache", server)
	}
	if a != 4 {
		t.Fatalf("apache count = %d want 4", a)
	}
}

func TestDetectServer_None(t *testing.T) {
	root := t.TempDir()
	mustWriteComm(t, root, "500", "bash")
	mustWriteComm(t, root, "501", "systemd")
	server, n, a := detectServer(root)
	if server != "none" || n != 0 || a != 0 {
		t.Fatalf("got (%q,%d,%d) want (none,0,0)", server, n, a)
	}
}

// fmtLogLine returns one combined-log-format line with the given
// timestamp and status code. The leading IP and the bracketed user
// field are placeholders; only the timestamp and status are load-
// bearing for the parser.
func fmtLogLine(ts time.Time, status int) string {
	return fmt.Sprintf(`10.0.0.1 - - [%s] "GET /x HTTP/1.1" %d 123 "-" "ua"`,
		ts.Format("02/Jan/2006:15:04:05 -0700"), status)
}

func TestParseAccessLogTail_Empty(t *testing.T) {
	r4, r5, _, anyParsed := parseAccessLogTail(nil, time.Now(), time.Hour)
	if anyParsed {
		t.Fatal("anyParsed should be false on empty tail")
	}
	if r4 != nil || r5 != nil {
		t.Fatalf("counts should be nil on empty tail; got 4xx=%v 5xx=%v", r4, r5)
	}
}

func TestParseAccessLogTail_MixedAllInWindow(t *testing.T) {
	now := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	inside := now.Add(-15 * time.Minute)
	body := ""
	for i := 0; i < 3; i++ {
		body += fmtLogLine(inside, 200) + "\n"
	}
	body += fmtLogLine(inside, 404) + "\n"
	body += fmtLogLine(inside, 404) + "\n"
	body += fmtLogLine(inside, 503) + "\n"
	r4, r5, _, anyParsed := parseAccessLogTail([]byte(body), now, time.Hour)
	if !anyParsed {
		t.Fatal("anyParsed should be true")
	}
	if r4 == nil || *r4 != 2 {
		t.Fatalf("recent_4xx: got %v want 2", r4)
	}
	if r5 == nil || *r5 != 1 {
		t.Fatalf("recent_5xx: got %v want 1", r5)
	}
}

func TestParseAccessLogTail_StatusOutsideWindowExcluded(t *testing.T) {
	now := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	inside := now.Add(-10 * time.Minute)
	outside := now.Add(-2 * time.Hour)
	body := fmtLogLine(inside, 404) + "\n" + fmtLogLine(outside, 500) + "\n"
	r4, r5, oldest, anyParsed := parseAccessLogTail([]byte(body), now, time.Hour)
	if !anyParsed {
		t.Fatal("anyParsed should be true")
	}
	if r4 == nil || *r4 != 1 {
		t.Fatalf("recent_4xx: got %v want 1", r4)
	}
	if r5 == nil || *r5 != 0 {
		t.Fatalf("recent_5xx: got %v want 0", r5)
	}
	if !oldest.Equal(outside) {
		t.Fatalf("oldestParsed: got %v want %v", oldest, outside)
	}
}

func TestParseAccessLogTail_GarbageFirstLineSkipped(t *testing.T) {
	now := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	inside := now.Add(-5 * time.Minute)
	body := "this is a partial line with no brackets\n" +
		fmtLogLine(inside, 404) + "\n"
	r4, r5, _, anyParsed := parseAccessLogTail([]byte(body), now, time.Hour)
	if !anyParsed {
		t.Fatal("anyParsed should be true (one good line)")
	}
	if r4 == nil || *r4 != 1 {
		t.Fatalf("recent_4xx: got %v want 1", r4)
	}
	if r5 == nil || *r5 != 0 {
		t.Fatalf("recent_5xx: got %v want 0", r5)
	}
}

// TestParseAccessLogTail_OldestNewerThanCutoff exercises the partial-
// coverage path: every line in the tail is newer than the cutoff, so
// the caller will classify coverage as "partial".
func TestParseAccessLogTail_OldestNewerThanCutoff(t *testing.T) {
	now := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	oldestLine := now.Add(-20 * time.Minute)
	newerLine := now.Add(-5 * time.Minute)
	body := fmtLogLine(oldestLine, 200) + "\n" + fmtLogLine(newerLine, 404) + "\n"
	_, _, oldest, anyParsed := parseAccessLogTail([]byte(body), now, time.Hour)
	if !anyParsed {
		t.Fatal("anyParsed should be true")
	}
	if !oldest.Equal(oldestLine) {
		t.Fatalf("oldestParsed: got %v want %v", oldest, oldestLine)
	}
	// Cutoff = now - 1h. oldestLine = now - 20m → newer than cutoff
	// → caller would mark coverage="partial".
	cutoff := now.Add(-time.Hour)
	if !oldest.After(cutoff) {
		t.Fatalf("oldestParsed %v should be after cutoff %v for partial coverage", oldest, cutoff)
	}
}

// TestParseAccessLogTail_CustomFormatNoQuotedStatus exercises the
// case where the operator runs a custom log_format that retains the
// bracketed timestamp but omits the quoted request field. Timestamps
// parse but no status is bucketable, so anyParsed=true with counts 0.
func TestParseAccessLogTail_CustomFormatNoQuotedStatus(t *testing.T) {
	now := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	inside := now.Add(-5 * time.Minute)
	tsStr := inside.Format("02/Jan/2006:15:04:05 -0700")
	body := fmt.Sprintf("10.0.0.1 [%s] GET /x 404 123\n", tsStr) +
		fmt.Sprintf("10.0.0.2 [%s] GET /y 500 0\n", tsStr)
	r4, r5, _, anyParsed := parseAccessLogTail([]byte(body), now, time.Hour)
	if !anyParsed {
		t.Fatal("anyParsed should be true (timestamps parsed)")
	}
	if r4 == nil || *r4 != 0 {
		t.Fatalf("recent_4xx: got %v want 0", r4)
	}
	if r5 == nil || *r5 != 0 {
		t.Fatalf("recent_5xx: got %v want 0", r5)
	}
}

func TestReadAccessLogTail_DiscardsPartialFirstLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	body := "first-line-incomplete-and-long-blob\nsecond complete line\nthird line\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// Pick a tail size that lands inside the first line.
	tail, err := readAccessLogTail(path, len(body)-5)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if want := "second complete line\nthird line\n"; string(tail) != want {
		t.Fatalf("tail = %q want %q", tail, want)
	}
}

func TestReadAccessLogTail_FileSmallerThanTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	body := "only line\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	tail, err := readAccessLogTail(path, 1024)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if string(tail) != body {
		t.Fatalf("tail = %q want %q", tail, body)
	}
}

func mustWriteComm(t *testing.T, root, pid, comm string) {
	t.Helper()
	dir := filepath.Join(root, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
