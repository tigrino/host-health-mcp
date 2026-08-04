package ops

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"host-health-mcp/daemon/internal/shared/linescan"
)

// A-10: the clamp used to run AFTER the accumulator, so a value that
// wrapped int64 and landed back inside [0, maxQueueDepth] passed both
// guards. "18446744073709551617" reported a queue depth of 1.
func TestPostqueueDepthSaturatesNotWraps(t *testing.T) {
	cases := map[string]int{
		"5":                    5,
		"0":                    0,
		"18446744073709551617": maxQueueDepth,
		"18446744073709551620": maxQueueDepth,
		"18446744073709551616": maxQueueDepth,
		"99999999999999999999": maxQueueDepth,
	}
	for in, want := range cases {
		out, err := parsePostqueueOutput([]byte("-- " + in + " Kbytes in " + in + " Requests.\n"))
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if out.QueueDepth != want {
			t.Errorf("depth for %q = %d, want %d", in, out.QueueDepth, want)
		}
	}
}

// M-2: a negative tail size made make() panic in the ROOT helper,
// which has no recover anywhere.
func TestReadAccessLogTailRejectsNonPositiveSize(t *testing.T) {
	for _, n := range []int{0, -1, -4096} {
		if _, err := readAccessLogTail("/var/log/nonexistent-for-test.log", n); err == nil {
			t.Errorf("tailBytes=%d was accepted", n)
		}
	}
}

// The access log is the one input a remote client fully controls: it
// writes the request URI and User-Agent into the line. One request
// with an over-long URI used to stop the scan silently, and because
// this is a TAIL read that line lands near the START of the window —
// so the counts came back near-zero, non-nil, with anyParsed true.
// The attacker suppressed the counter meant to detect them and the
// response still said status: ok.
func TestParseAccessLogTailRefusesTruncatedInput(t *testing.T) {
	now := time.Now()
	ts := now.Add(-time.Minute).Format("02/Jan/2006:15:04:05 -0700")
	good := func(code int) string {
		return `10.0.0.1 - - [` + ts + `] "GET / HTTP/1.1" ` + strconv.Itoa(code) + " 100\n"
	}

	// Baseline: well-formed input counts normally.
	var sane strings.Builder
	for i := 0; i < 5; i++ {
		sane.WriteString(good(503))
	}
	r4, r5, _, anyParsed := parseAccessLogTail([]byte(sane.String()), now, time.Hour)
	if !anyParsed || r5 == nil || *r5 != 5 {
		t.Fatalf("baseline: anyParsed=%v r5=%v, want 5", anyParsed, r5)
	}

	// Some real traffic, THEN the poison, then the traffic the attacker
	// wants hidden. This ordering is the whole point: with the error
	// discarded the scan stops mid-file having counted only the first
	// group, so the result is non-nil, anyParsed is true, and the
	// number published is an undercount presented as a total. Putting
	// the long line first would make nothing parse at all, which fails
	// safe by accident and would not exercise the fix.
	var poisoned strings.Builder
	poisoned.WriteString(good(503))
	poisoned.WriteString("10.0.0.1 - - [" + ts + `] "GET /` + strings.Repeat("A", linescan.MaxLine+1) + "\n")
	for i := 0; i < 20; i++ {
		poisoned.WriteString(good(503))
	}
	r4, r5, _, anyParsed = parseAccessLogTail([]byte(poisoned.String()), now, time.Hour)
	if anyParsed || r4 != nil || r5 != nil {
		t.Errorf("a truncated scan reported counts: anyParsed=%v r4=%v r5=%v", anyParsed, r4, r5)
	}
}
