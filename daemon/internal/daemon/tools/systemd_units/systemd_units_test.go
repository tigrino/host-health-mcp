package systemdunits

import (
	"testing"

	"github.com/coreos/go-systemd/v22/dbus"
)

func rows(names ...string) []dbus.UnitStatus {
	out := make([]dbus.UnitStatus, 0, len(names))
	for _, n := range names {
		out = append(out, dbus.UnitStatus{Name: n})
	}
	return out
}

func names(us []dbus.UnitStatus) []string {
	out := make([]string, 0, len(us))
	for _, u := range us {
		out = append(out, u.Name)
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestExcludeNamedKeepsArraysDisjoint covers the rule that a unit
// both named exactly and matched by a pattern appears only in units[],
// never in both. Duplication would make a consumer reading the two
// arrays together double-count.
func TestExcludeNamedKeepsArraysDisjoint(t *testing.T) {
	cases := []struct {
		name    string
		matched []dbus.UnitStatus
		exact   []dbus.UnitStatus
		want    []string
	}{
		{
			name:    "overlap is removed from the pattern set",
			matched: rows("nginx.service", "nginx-extra.service"),
			exact:   rows("nginx.service"),
			want:    []string{"nginx-extra.service"},
		},
		{
			name:    "no overlap passes through",
			matched: rows("nginx.service"),
			exact:   rows("sshd.service"),
			want:    []string{"nginx.service"},
		},
		{
			name:    "empty exact selector is a no-op",
			matched: rows("nginx.service"),
			exact:   nil,
			want:    []string{"nginx.service"},
		},
		{
			name:    "every match already named yields nothing",
			matched: rows("a.service", "b.service"),
			exact:   rows("a.service", "b.service"),
			want:    []string{},
		},
	}
	for _, c := range cases {
		got := names(excludeNamed(c.matched, c.exact))
		if !equal(got, c.want) {
			t.Errorf("%s: excludeNamed = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestSortUnits pins the ordering the response and its cache key
// depend on; D-Bus does not promise an order.
func TestSortUnits(t *testing.T) {
	got := names(sortUnits(rows("z.service", "a.service", "m.service")))
	want := []string{"a.service", "m.service", "z.service"}
	if !equal(got, want) {
		t.Errorf("sortUnits = %v, want %v", got, want)
	}
}

// TestCapUnits covers the expansion bound. Each surviving unit costs
// two further D-Bus round trips, so a broad pattern must be truncated
// rather than allowed to blow the per-call deadline.
func TestCapUnits(t *testing.T) {
	cases := []struct {
		total       int
		max         int
		wantKept    int
		wantDropped int
	}{
		{total: 0, max: maxPatternUnits, wantKept: 0, wantDropped: 0},
		{total: 5, max: maxPatternUnits, wantKept: 5, wantDropped: 0},
		{total: 100, max: maxPatternUnits, wantKept: 100, wantDropped: 0},
		{total: 101, max: maxPatternUnits, wantKept: 100, wantDropped: 1},
		{total: 400, max: maxPatternUnits, wantKept: 100, wantDropped: 300},
	}
	for _, c := range cases {
		in := make([]dbus.UnitStatus, c.total)
		kept, dropped := capUnits(in, c.max)
		if len(kept) != c.wantKept || dropped != c.wantDropped {
			t.Errorf("capUnits(%d, %d) = (%d kept, %d dropped), want (%d, %d)",
				c.total, c.max, len(kept), dropped, c.wantKept, c.wantDropped)
		}
	}
}

// TestNewCopiesSelectors guards against the caller retaining a handle
// on the manifest slices and mutating the tool's view after start.
func TestNewCopiesSelectors(t *testing.T) {
	exact := []string{"sshd.service"}
	pats := []string{"nginx*"}
	tool := New(exact, pats)
	exact[0] = "mutated.service"
	pats[0] = "mutated*"
	if tool.whitelisted[0] != "sshd.service" {
		t.Errorf("whitelisted aliases the caller's slice: %q", tool.whitelisted[0])
	}
	if tool.patterns[0] != "nginx*" {
		t.Errorf("patterns aliases the caller's slice: %q", tool.patterns[0])
	}
}
