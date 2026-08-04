package ops

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A-3: this was the only op of 23 with no parameter allow-list.
// access_log_path reached the opener verbatim from the request, and the
// request comes from the daemon — the network-facing half the helper
// exists to be separate from.
func TestCheckAccessLogPath(t *testing.T) {
	restoreAccessLogPrefixes(t)
	SetAccessLogPrefixes([]string{"/var/log/"})

	allowed := []string{
		"/var/log/nginx/access.log",
		"/var/log/apache2/other_vhosts_access.log",
		"/var/log/access.log",
	}
	for _, p := range allowed {
		if err := checkAccessLogPath(p); err != nil {
			t.Errorf("checkAccessLogPath(%q) = %v, want allowed", p, err)
		}
	}

	rejected := []string{
		"/etc/shadow",
		"/root/.ssh/id_ed25519",
		"/proc/self/environ",
		"relative/path.log",
		"",
		// Traversal must not walk out of the prefix.
		"/var/log/../etc/shadow",
		"/var/log/nginx/../../../etc/shadow",
		// Prefix must be directory-bounded, not a string prefix.
		"/var/logsecrets/passwords",
		"/var/log",
	}
	for _, p := range rejected {
		if err := checkAccessLogPath(p); err == nil {
			t.Errorf("checkAccessLogPath(%q) accepted; it is outside the allow-list", p)
		}
	}
}

// An empty allow-list must keep the default rather than permitting
// everything — a deny-list that empties to "allow all" is the fail-open
// shape this exists to remove.
func TestSetAccessLogPrefixesEmptyKeepsDefault(t *testing.T) {
	restoreAccessLogPrefixes(t)
	SetAccessLogPrefixes([]string{"/srv/logs"})
	if err := checkAccessLogPath("/srv/logs/a.log"); err != nil {
		t.Fatalf("custom prefix not applied: %v", err)
	}
	SetAccessLogPrefixes(nil)
	if err := checkAccessLogPath("/srv/logs/a.log"); err != nil {
		t.Errorf("nil input should have kept the previous list, got %v", err)
	}
	SetAccessLogPrefixes([]string{"", "   ", "relative"})
	if err := checkAccessLogPath("/etc/shadow"); err == nil {
		t.Error("a list of invalid entries opened the allow-list to everything")
	}
}

// restoreAccessLogPrefixes puts the package global back however the
// test exits, including on t.Fatal. Restoring by hand at the end leaks
// the override to every later test in the package when it does not.
func restoreAccessLogPrefixes(t *testing.T) {
	t.Helper()
	saved := append([]string(nil), accessLogAllowedPrefixes...)
	t.Cleanup(func() { accessLogAllowedPrefixes = saved })
}

// The fstat on the opened descriptor must reject a non-regular file,
// and O_NONBLOCK must keep the open itself from waiting for a writer.
//
// This does NOT demonstrate the TOCTOU fix — a race is not expressible
// as a unit test, and the old stat-then-open code passes this too
// (os.Stat never blocks on a FIFO either). The TOCTOU window is closed
// by construction: the fstat applies to the same descriptor that is
// read, so there is no second resolution to race. Named for what it
// asserts.
func TestReadAccessLogTailRejectsANonRegularFile(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "access.log")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readAccessLogTail(fifo, 4096)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a FIFO was accepted as an access log")
		}
	case <-timeoutAfter():
		t.Fatal("readAccessLogTail blocked on a FIFO; the open(2) window is still there")
	}
}

// A symlinked final component must be refused outright: a compromised
// web worker replacing the access log with a link would otherwise have
// the root helper read the target.
func TestReadAccessLogTailRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "secret")
	if err := os.WriteFile(target, []byte("sensitive\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "access.log")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := readAccessLogTail(link, 4096); err == nil {
		t.Error("a symlinked access log was followed")
	} else if !strings.Contains(err.Error(), "too many levels") &&
		!strings.Contains(err.Error(), "symbolic link") &&
		!strings.Contains(err.Error(), "ELOOP") {
		t.Logf("refused with: %v", err)
	}
}

// A regular file still reads normally.
func TestReadAccessLogTailReadsARegularFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "access.log")
	if err := os.WriteFile(p, []byte("line one\nline two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readAccessLogTail(p, 4096)
	if err != nil {
		t.Fatalf("readAccessLogTail: %v", err)
	}
	if !strings.Contains(string(got), "line two") {
		t.Errorf("got %q", got)
	}
}

func timeoutAfter() <-chan time.Time { return time.After(5 * time.Second) }
