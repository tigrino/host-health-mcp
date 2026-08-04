package ops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// aideLog writes a log whose parsed change_count is n, with the given
// modification time so the newest-first ordering is deterministic.
func aideLog(t *testing.T, dir, name string, n int, age time.Duration) {
	t.Helper()
	p := filepath.Join(dir, name)
	body := "AIDE found differences between database and filesystem!!\n" +
		"Summary:\n  Total number of entries:\t1000\n" +
		"  Added entries:\t\t" + itoa(n) + "\n  Removed entries:\t\t0\n  Changed entries:\t\t0\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	mt := time.Now().Add(-age)
	if err := os.Chtimes(p, mt, mt); err != nil {
		t.Fatal(err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func withAideDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	orig := aideLogDir
	aideLogDir = d
	t.Cleanup(func() { aideLogDir = orig })
	return d
}

// POSITIVE: the newest log wins.
func TestReadAideLogPrefersTheNewestLog(t *testing.T) {
	d := withAideDir(t)
	aideLog(t, d, "aide.log", 3, 0)
	aideLog(t, d, "aide.log.1", 99, time.Hour)

	cnt, _ := readAideLog()
	if cnt == nil {
		t.Fatal("no count parsed")
	}
	if *cnt != 3 {
		t.Errorf("change_count = %d, want 3 (the current log)", *cnt)
	}
}

// NEGATIVE: a truncated CURRENT log must not fall through to the
// previous rotated one.
//
// The caller walks candidates newest-first and treats a nil count as
// "not in this file", so returning nil on truncation made it report
// LAST WEEK's change_count as the current run — a file-integrity
// checker publishing a stale zero as fresh evidence, which is a false
// negative dressed as data. Reporting nothing is correct here.
func TestReadAideLogDoesNotFallThroughOnTruncation(t *testing.T) {
	d := withAideDir(t)

	// Current log: truncated by an over-long line.
	huge := "AIDE found differences between database and filesystem!!\n" +
		strings.Repeat("x", 1<<20+1) + "\n  Added entries:\t\t7\n"
	p := filepath.Join(d, "aide.log")
	if err := os.WriteFile(p, []byte(huge), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := os.Chtimes(p, now, now); err != nil {
		t.Fatal(err)
	}

	// Older rotated log with a perfectly parseable count.
	aideLog(t, d, "aide.log.1", 42, time.Hour)

	cnt, _ := readAideLog()
	if cnt != nil && *cnt == 42 {
		t.Fatal("fell through to the previous rotated log; last week's change_count " +
			"would be published as the current run")
	}
	if cnt != nil {
		t.Errorf("change_count = %d, want nil (unknown) after a truncated current log", *cnt)
	}
}
