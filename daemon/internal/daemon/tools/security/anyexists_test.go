package security

import (
	"os"
	"path/filepath"
	"testing"
)

// C-8: a stat error other than ErrNotExist used to count as "present",
// so a permission problem made the tool report AIDE, auditd, rkhunter
// or fail2ban as INSTALLED when it had no idea. For a security-posture
// tool "cannot verify" must never render as "verified present".
func TestAnyExistsDoesNotFailOpen(t *testing.T) {
	dir := t.TempDir()

	real := filepath.Join(dir, "present")
	if err := os.WriteFile(real, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if present, uncertain := anyExists(real); !present || uncertain != nil {
		t.Errorf("an existing path: present=%v uncertain=%v, want true/nil", present, uncertain)
	}

	absent := filepath.Join(dir, "absent")
	if present, uncertain := anyExists(absent); present || uncertain != nil {
		t.Errorf("a missing path: present=%v uncertain=%v, want false/nil", present, uncertain)
	}

	// ENOTDIR: a path that traverses through a regular file. Not
	// ErrNotExist, and previously reported as present.
	through := filepath.Join(real, "child")
	present, uncertain := anyExists(through)
	if present {
		t.Error("an unstattable path was reported as present")
	}
	if uncertain == nil {
		t.Error("the uncertainty was swallowed; the caller cannot warn")
	}

	// An outright hit still wins over an uncertain sibling.
	if present, _ := anyExists(through, real); !present {
		t.Error("a definite hit alongside an uncertain path should be present")
	}
}
