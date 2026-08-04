package kernel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withVmstat(t *testing.T, body string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "vmstat")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := procVmstatPath
	procVmstatPath = p
	t.Cleanup(func() { procVmstatPath = orig })
}

// POSITIVE: a normal vmstat yields the counter.
func TestReadOOMKillsReadsTheCounter(t *testing.T) {
	withVmstat(t, "nr_free_pages 1000\noom_kill 7\npgfault 5\n")
	if got := readOOMKills(); got != 7 {
		t.Errorf("readOOMKills() = %d, want 7", got)
	}
}

// NEGATIVE: a truncated read must report UNKNOWN, not zero.
//
// The caller tests `kills >= 0`, so returning 0 asserts "this host has
// had zero OOM kills" on the strength of a read that failed — the
// opposite of what the guard's comment claims, and the exact defect
// the first attempt at this shipped.
func TestReadOOMKillsReportsUnknownOnTruncatedRead(t *testing.T) {
	withVmstat(t, "nr_free_pages 1000\n"+strings.Repeat("x", 1<<20+1)+"\noom_kill 7\n")
	got := readOOMKills()
	if got == 0 {
		t.Fatal("a truncated read reported 0 OOM kills; the caller publishes that as a real count")
	}
	if got != -1 {
		t.Errorf("readOOMKills() = %d, want -1 (the unknown sentinel the caller tests for)", got)
	}
}

// NEGATIVE: an absent vmstat is also unknown, not zero.
func TestReadOOMKillsUnknownWhenSourceMissing(t *testing.T) {
	orig := procVmstatPath
	procVmstatPath = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { procVmstatPath = orig })
	if got := readOOMKills(); got != -1 {
		t.Errorf("readOOMKills() = %d, want -1", got)
	}
}
