package config

import (
	"math"
	"testing"
	"time"
)

func TestOpDeadline(t *testing.T) {
	cases := []struct {
		name     string
		cfg      Config
		op       string
		callerMS int
		want     time.Duration
	}{
		{
			name: "no override and no caller budget uses the default",
			cfg:  Defaults(),
			op:   "smart_summary",
			want: DefaultOpDeadline,
		},
		{
			name: "a helper.yml override replaces the default",
			cfg:  Config{OpDeadlineMS: map[string]int{"smart_summary": 4000}},
			op:   "smart_summary",
			want: 4 * time.Second,
		},
		{
			name: "an override for a different op does not apply",
			cfg:  Config{OpDeadlineMS: map[string]int{"zpool_status": 4000}},
			op:   "smart_summary",
			want: DefaultOpDeadline,
		},
		{
			// The daemon's remaining budget. Honouring it is what lets
			// the helper's SIGTERM/SIGKILL chain finish before the
			// daemon stops waiting.
			name:     "a shorter caller budget wins",
			cfg:      Defaults(),
			op:       "smart_summary",
			callerMS: 2000,
			want:     2 * time.Second,
		},
		{
			// The peer is the thing being defended against: a caller
			// asking for more time than the local config allows must
			// not get it.
			name:     "a longer caller budget is ignored",
			cfg:      Defaults(),
			op:       "smart_summary",
			callerMS: 600000,
			want:     DefaultOpDeadline,
		},
		{
			name:     "a caller budget longer than a short override is ignored",
			cfg:      Config{OpDeadlineMS: map[string]int{"smart_summary": 1000}},
			op:       "smart_summary",
			callerMS: 9000,
			want:     time.Second,
		},
		{
			name: "an absurd override is clamped to the maximum",
			cfg:  Config{OpDeadlineMS: map[string]int{"smart_summary": 86400000}},
			op:   "smart_summary",
			want: MaxOpDeadline,
		},
		{
			name:     "a tiny caller budget is floored, never zero",
			cfg:      Defaults(),
			op:       "smart_summary",
			callerMS: 1,
			want:     MinOpDeadline,
		},
		{
			name: "a zero override falls back to the default rather than disabling the deadline",
			cfg:  Config{OpDeadlineMS: map[string]int{"smart_summary": 0}},
			op:   "smart_summary",
			want: DefaultOpDeadline,
		},
		{
			name: "a negative override falls back to the default",
			cfg:  Config{OpDeadlineMS: map[string]int{"smart_summary": -1}},
			op:   "smart_summary",
			want: DefaultOpDeadline,
		},
		{
			name:     "a negative caller budget is ignored",
			cfg:      Defaults(),
			op:       "smart_summary",
			callerMS: -5000,
			want:     DefaultOpDeadline,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.OpDeadline(tc.op, tc.callerMS); got != tc.want {
				t.Errorf("OpDeadline(%q, %d) = %v, want %v", tc.op, tc.callerMS, got, tc.want)
			}
		})
	}
}

// Whatever the inputs, the resolved deadline is always usable: never
// zero (which context.WithTimeout treats as already expired) and never
// unbounded. This is the property A-1 was about.
func TestOpDeadlineIsAlwaysBounded(t *testing.T) {
	cfgs := []Config{
		Defaults(),
		{},
		{OpDeadlineMS: map[string]int{"op": 0}},
		{OpDeadlineMS: map[string]int{"op": -100}},
		{OpDeadlineMS: map[string]int{"op": 1}},
		{OpDeadlineMS: map[string]int{"op": 1 << 30}},
	}
	callers := []int{-1, 0, 1, 500, 9500, 1 << 30}

	for _, c := range cfgs {
		for _, ms := range callers {
			got := c.OpDeadline("op", ms)
			if got < MinOpDeadline {
				t.Errorf("cfg %+v caller %d: %v below MinOpDeadline %v", c.OpDeadlineMS, ms, got, MinOpDeadline)
			}
			if got > MaxOpDeadline {
				t.Errorf("cfg %+v caller %d: %v above MaxOpDeadline %v", c.OpDeadlineMS, ms, got, MaxOpDeadline)
			}
		}
	}
}

// The default has to leave the helper room to escalate SIGTERM ->
// KillGrace -> SIGKILL inside the daemon's own per-tool timeout, which
// REQ 5.1 caps at 10 s. exec.go documents that relationship; before
// A-1 it described a mechanism that did not exist.
func TestDefaultOpDeadlineFitsTheDaemonTimeoutCap(t *testing.T) {
	const daemonMaxTimeout = 10 * time.Second
	const killGrace = 500 * time.Millisecond
	if DefaultOpDeadline+killGrace > daemonMaxTimeout {
		t.Errorf("DefaultOpDeadline %v + KillGrace %v exceeds the daemon's %v cap",
			DefaultOpDeadline, killGrace, daemonMaxTimeout)
	}
}

// m-2: time.Duration(ms) * time.Millisecond overflows int64 nanoseconds
// above ~9.2e9 ms and goes negative. The Min clamp would rescue the
// result by accident; msToDuration makes it saturate by construction,
// so "a peer may only shorten, never extend" survives a refactor.
func TestOpDeadlineOverflowSaturates(t *testing.T) {
	huge := []int{math.MaxInt32, math.MaxInt64 / int64ms, math.MaxInt}
	for _, ms := range huge {
		t.Run("caller", func(t *testing.T) {
			got := Defaults().OpDeadline("op", ms)
			if got != DefaultOpDeadline {
				t.Errorf("caller budget %d ms: got %v, want the local default %v "+
					"(an overflowing peer value must not shorten or extend anything)",
					ms, got, DefaultOpDeadline)
			}
		})
		t.Run("override", func(t *testing.T) {
			cfg := Config{OpDeadlineMS: map[string]int{"op": ms}}
			got := cfg.OpDeadline("op", 0)
			if got != MaxOpDeadline {
				t.Errorf("override %d ms: got %v, want %v", ms, got, MaxOpDeadline)
			}
		})
	}
}

const int64ms = int(time.Millisecond)

// The peer must never be able to drive the deadline below the floor,
// which would fail every op instead of bounding it.
func TestOpDeadlineFloorSurvivesAHostilePeer(t *testing.T) {
	for _, ms := range []int{1, 2, 100, 249} {
		if got := Defaults().OpDeadline("op", ms); got != MinOpDeadline {
			t.Errorf("caller budget %d ms: got %v, want the %v floor", ms, got, MinOpDeadline)
		}
	}
}

// MaxOpDeadline exists to bound an operator typo. Keeping it near the
// daemon's own 10 s ceiling is the point: a far larger value lets a
// typo reproduce the exact symptom A-1 removed, just finitely.
func TestMaxOpDeadlineStaysNearTheDaemonCeiling(t *testing.T) {
	const daemonMaxTimeout = 10 * time.Second
	if MaxOpDeadline > 2*daemonMaxTimeout {
		t.Errorf("MaxOpDeadline %v is more than twice the daemon's %v cap; "+
			"a helper.yml typo could outlive the request by that margin",
			MaxOpDeadline, daemonMaxTimeout)
	}
	if MaxOpDeadline < DefaultOpDeadline {
		t.Errorf("MaxOpDeadline %v is below DefaultOpDeadline %v", MaxOpDeadline, DefaultOpDeadline)
	}
}
