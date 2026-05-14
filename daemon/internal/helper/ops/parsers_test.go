package ops

import (
	"strings"
	"testing"
)

func TestSummariseScan(t *testing.T) {
	cases := map[string]string{
		"none requested":                                "idle",
		"scrub in progress since Sun ...":               "scrubbing",
		"resilver in progress since ...":                "resilvering",
		"scrub repaired 0B in 00:30:00 with 0 errors":   "scrubbed",
		"scrub completed":                               "scrubbed",
		"resilver completed":                            "resilvered",
		"something else entirely":                       "unknown",
	}
	for in, want := range cases {
		if got := summariseScan(in); got != want {
			t.Errorf("summariseScan(%q) = %q want %q", in, got, want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]int{
		"No known data errors": 0,
		"3 data errors":        3,
		"42":                   42,
	}
	for in, want := range cases {
		if got := parseErrors(in); got != want {
			t.Errorf("parseErrors(%q) = %d want %d", in, got, want)
		}
	}
}

func TestParseZpoolStatus(t *testing.T) {
	in := `  pool: tank
 state: ONLINE
  scan: scrub repaired 0B in 00:30:00 with 0 errors on Sun Apr 1 02:00:00 2024
config:

	NAME        STATE     READ WRITE CKSUM
	tank        ONLINE       0     0     0

errors: No known data errors
`
	p := parseZpoolStatus("tank", []byte(in))
	if p.State != "ONLINE" {
		t.Errorf("State = %q want ONLINE", p.State)
	}
	if p.ScanState != "scrubbed" {
		t.Errorf("ScanState = %q want scrubbed", p.ScanState)
	}
	if p.ErrorsTotal != 0 {
		t.Errorf("ErrorsTotal = %d want 0", p.ErrorsTotal)
	}
}

const fakeAideLog = `
AIDE 0.17 found differences between database and filesystem!!
Start timestamp: 2024-01-01 03:00:00 +0000 (AIDE 0.17)
End timestamp: 2024-01-01 03:00:05 +0000 (run time: 5 seconds)

Summary:
  Total number of entries:	1234
  Added entries:		2
  Removed entries:		0
  Changed entries:		1
`

func TestParseAideLog(t *testing.T) {
	cnt, _ := parseAideLog([]byte(fakeAideLog))
	if cnt == nil {
		t.Fatal("change count not detected")
	}
	if *cnt != 3 {
		t.Errorf("change count = %d want 3 (added+removed+changed)", *cnt)
	}
}

func TestParseAideLogFallbackToDifferencesLine(t *testing.T) {
	in := `Total number of differences: 7`
	cnt, _ := parseAideLog([]byte(in))
	if cnt == nil || *cnt != 7 {
		t.Errorf("differences fallback: got %v want 7", cnt)
	}
}

func TestCountAptUpgrades(t *testing.T) {
	in := `Reading package lists...
Building dependency tree...
The following packages will be upgraded:
  apt curl libssl3
3 upgraded, 0 newly installed, 0 to remove, 0 not upgraded.
Inst libssl3 [3.0.11-1] (3.0.13-1 Debian:12.5/stable, Debian:12-security)
Inst curl [7.88.1-10] (7.88.1-11 Debian:12.5/stable, Debian:12.5/stable [amd64])
Inst apt [2.6.1] (2.7.0 Debian:12.5/stable)
Conf libssl3 (3.0.13-1)
Conf curl (7.88.1-11)
`
	sec, reg := countUpgrades([]byte(in))
	// libssl3's pocket includes "security"; curl + apt do not.
	if sec != 1 {
		t.Errorf("security count = %d want 1", sec)
	}
	if reg != 2 {
		t.Errorf("regular count = %d want 2", reg)
	}
}

func TestExtractHeld(t *testing.T) {
	in := `apt					install
libfoo-dev				hold
curl					install
weird-pkg				hold
`
	got := extractHeld([]byte(in))
	if len(got) != 2 {
		t.Fatalf("len = %d want 2; got %v", len(got), got)
	}
	if !strings.Contains(strings.Join(got, ","), "libfoo-dev") {
		t.Errorf("missing libfoo-dev: %v", got)
	}
}
