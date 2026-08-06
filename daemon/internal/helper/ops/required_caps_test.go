package ops

import (
	"testing"

	"host-health-mcp/daemon/internal/shared/capsplan"
)

// RequiredCap mirrors the grant rules in capsplan: one decides what the
// helper GETS at install time, the other decides when to warn that it
// did not get it. They run in different processes at different times,
// so nothing but a test keeps them honest.
//
// Until 2.4.0 these two tests scraped `add CAP_...` out of the shell
// generator with a regexp. That proved the string appeared in a file,
// not that the rules could ever produce it — a grant moved behind a
// condition that never fires would still have matched. The generator's
// rules are now an importable package, so this asks them directly.
func TestRequiredCapsAreGrantableByTheGenerator(t *testing.T) {
	grantable := map[string]bool{}
	for _, c := range capsplan.EveryGrantableCapability() {
		grantable[c] = true
	}
	if len(grantable) == 0 {
		t.Fatal("the generator grants nothing; the test is not proving anything")
	}

	for op, capName := range RequiredCap {
		if !grantable[capName] {
			t.Errorf("op %q requires %s, but no combination of manifest entries "+
				"causes the generator to grant it — the helper would warn about "+
				"a missing capability on every host, forever", op, capName)
		}
	}
}

// Every capability the generator can grant should be reachable from
// some op, or it is unnecessary privilege in the bounding set of a root
// process.
func TestGeneratorGrantsAreJustified(t *testing.T) {
	used := map[string]bool{}
	for _, c := range RequiredCap {
		used[c] = true
	}
	// CAP_CHOWN is for the helper's own socket and runtime directory,
	// not for any op.
	used["CAP_CHOWN"] = true
	// CAP_DAC_READ_SEARCH covers file reads across many ops and fails
	// loudly (EACCES) rather than silently, so it is deliberately not
	// in RequiredCap.
	used["CAP_DAC_READ_SEARCH"] = true

	for _, c := range capsplan.EveryGrantableCapability() {
		if !used[c] {
			t.Errorf("the generator can grant %s but no op declares needing it; "+
				"either an op is missing from RequiredCap or the grant is "+
				"unnecessary privilege in a root process", c)
		}
	}
}
