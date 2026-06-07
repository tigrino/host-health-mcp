package security

import (
	"os"
	"path/filepath"
	"testing"
)

// aideCleanLog is an AIDE "no differences" report (0.18.3 shape): the
// clean-state headline plus a database-attributes section, with none of
// the "Total number of differences:" / "Added/Removed/Changed entries:"
// summary lines that a changed run carries.
const aideCleanLog = `Start timestamp: 2024-01-01 03:00:00 +0000 (AIDE 0.18.3)
AIDE found NO differences between database and filesystem. Looks okay!!

Number of entries:    29814

---------------------------------------------------
The attributes of the (uncompressed) database(s):
---------------------------------------------------

/var/lib/aide/aide.db
 MD5       : AAAAAAAAAAAAAAAAAAAAAA==
 SHA256    : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
             AAAAAAAA=
 GOST      : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
             AAAAAAAA=

End timestamp: 2024-01-01 03:00:20 +0000 (run time: 0m 19s)
`

const aideDiffLog = `Start timestamp: 2024-01-01 03:00:00 +0000 (AIDE 0.18.3)
AIDE found differences between database and filesystem!!

Summary:
  Total number of entries:	29814
  Added entries:		0
  Removed entries:		0
  Changed entries:		2

End timestamp: 2024-01-01 03:00:20 +0000 (run time: 0m 19s)
`

func writeAideLog(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "aide.log")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// Regression for the AIDE 0.18.3 report: a clean operator log
// must force change_count=0 even when the helper op pre-seeded a stale
// non-zero count parsed from a different/rotated /var/log/aide log.
// Before the fix the no-diff branch only filled change_count when nil,
// so exit=0 shipped alongside the stale 21.
func TestFillAideFromLogCleanOverridesStaleCount(t *testing.T) {
	tool := New(nil, "", writeAideLog(t, aideCleanLog))
	stale := 21
	d := Aide{Present: true, ChangeCount: &stale}
	tool.fillAideFromLog(&d, func(string) {})

	if d.LastExitCode == nil || *d.LastExitCode != 0 {
		t.Fatalf("last_exit_code = %v, want 0", d.LastExitCode)
	}
	if d.ChangeCount == nil || *d.ChangeCount != 0 {
		t.Fatalf("change_count = %v, want 0 (stale 21 must be overridden)", d.ChangeCount)
	}
}

func TestFillAideFromLogCleanNilCount(t *testing.T) {
	tool := New(nil, "", writeAideLog(t, aideCleanLog))
	d := Aide{Present: true}
	tool.fillAideFromLog(&d, func(string) {})

	if d.LastExitCode == nil || *d.LastExitCode != 0 {
		t.Fatalf("last_exit_code = %v, want 0", d.LastExitCode)
	}
	if d.ChangeCount == nil || *d.ChangeCount != 0 {
		t.Fatalf("change_count = %v, want 0", d.ChangeCount)
	}
}

func TestFillAideFromLogDiffCounts(t *testing.T) {
	tool := New(nil, "", writeAideLog(t, aideDiffLog))
	stale := 99
	d := Aide{Present: true, ChangeCount: &stale}
	tool.fillAideFromLog(&d, func(string) {})

	if d.LastExitCode == nil || *d.LastExitCode != 1 {
		t.Fatalf("last_exit_code = %v, want 1", d.LastExitCode)
	}
	if d.ChangeCount == nil || *d.ChangeCount != 2 {
		t.Fatalf("change_count = %v, want 2", d.ChangeCount)
	}
}
