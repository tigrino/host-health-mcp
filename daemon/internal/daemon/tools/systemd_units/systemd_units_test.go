package systemdunits

import (
	"strings"
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

// TestPlanLeavesExactOrderUntouched is the regression test for the
// 2.2.0 ordering bug. ListUnitsByNames returns rows in the order of the
// names it was given, so units[] comes back in manifest order; 2.2.0
// sorted it alphabetically as well, silently reordering the array for
// every consumer that already existed. plan() must hand the exact rows
// back exactly as received.
func TestPlanLeavesExactOrderUntouched(t *testing.T) {
	named := rows("zebra.service", "alpha.service", "middle.service")
	exact, _, _ := plan(named, nil)
	want := []string{"zebra.service", "alpha.service", "middle.service"}
	if !equal(names(exact), want) {
		t.Errorf("plan reordered units[]: got %v, want manifest order %v", names(exact), want)
	}
}

// TestPlanSortsOnlyPatternResults: ListUnitsByPatterns walks systemd's
// unit hashmap, so that order is not meaningful and must be normalised.
func TestPlanSortsOnlyPatternResults(t *testing.T) {
	_, pattern, _ := plan(nil, rows("c.service", "a.service", "b.service"))
	want := []string{"a.service", "b.service", "c.service"}
	if !equal(names(pattern), want) {
		t.Errorf("pattern_units not sorted: got %v, want %v", names(pattern), want)
	}
}

// TestPlanDisjoint asserts the two arrays never carry the same unit.
func TestPlanDisjoint(t *testing.T) {
	named := rows("nginx.service")
	matched := rows("nginx.service", "nginx-extra.service")
	exact, pattern, _ := plan(named, matched)
	if !equal(names(exact), []string{"nginx.service"}) {
		t.Errorf("units[] = %v", names(exact))
	}
	if !equal(names(pattern), []string{"nginx-extra.service"}) {
		t.Errorf("pattern_units[] = %v, want the collision removed", names(pattern))
	}
}

// TestPlanWarningArithmetic pins the reported total. The count is taken
// after exclusion and after truncation, so it must reconstruct the
// pre-truncation figure rather than reporting the capped length.
func TestPlanWarningArithmetic(t *testing.T) {
	if _, _, w := plan(nil, make([]dbus.UnitStatus, maxPatternUnits)); len(w) != 0 {
		t.Errorf("warning emitted at exactly the cap: %v", w)
	}
	_, pattern, warnings := plan(nil, make([]dbus.UnitStatus, maxPatternUnits+37))
	if len(pattern) != maxPatternUnits {
		t.Fatalf("pattern_units length = %d, want %d", len(pattern), maxPatternUnits)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected exactly one warning, got %v", warnings)
	}
	if !strings.Contains(warnings[0], "137") {
		t.Errorf("warning should report the pre-truncation total 137: %q", warnings[0])
	}
	if !strings.Contains(warnings[0], "100") {
		t.Errorf("warning should report the cap: %q", warnings[0])
	}
}

// TestPlanNoPatternsConfigured is the common case: an unchanged 2.1.0
// manifest. Nothing may be added, dropped, reordered, or warned about.
func TestPlanNoPatternsConfigured(t *testing.T) {
	named := rows("sshd.service", "cron.service")
	exact, pattern, warnings := plan(named, nil)
	if !equal(names(exact), []string{"sshd.service", "cron.service"}) {
		t.Errorf("units[] = %v", names(exact))
	}
	if len(pattern) != 0 {
		t.Errorf("pattern_units[] = %v, want empty", names(pattern))
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}
