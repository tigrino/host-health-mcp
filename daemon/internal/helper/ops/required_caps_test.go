package ops

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// RequiredCap mirrors the grant table in caps-template.sh: one decides
// what the helper GETS at install time, the other decides when to warn
// that it did not get it. They are in different languages and run at
// different times, so nothing but a test keeps them honest.
//
// A capability named here that the generator never grants would warn on
// every host forever. A capability the generator grants for an op that
// is missing here is a silence this warning was meant to break.
func TestRequiredCapsAppearInTheGenerator(t *testing.T) {
	gen := filepath.Join("..", "..", "..", "..", "build", "postinst", "caps-template.sh")
	b, err := os.ReadFile(gen)
	if err != nil {
		t.Fatalf("read generator: %v", err)
	}
	body := string(b)

	for op, capName := range RequiredCap {
		if !strings.Contains(body, capName) {
			t.Errorf("op %q requires %s, but the generator never grants it — "+
				"this would warn on every host", op, capName)
		}
	}
}

// Every capability the generator can grant should be reachable from
// some op, or the grant is dead weight in the bounding set of a root
// process.
func TestGeneratorGrantsAreJustified(t *testing.T) {
	gen := filepath.Join("..", "..", "..", "..", "build", "postinst", "caps-template.sh")
	b, err := os.ReadFile(gen)
	if err != nil {
		t.Fatal(err)
	}
	granted := map[string]bool{}
	for _, m := range regexp.MustCompile(`add (CAP_[A-Z_]+)`).FindAllStringSubmatch(string(b), -1) {
		granted[m[1]] = true
	}
	if len(granted) == 0 {
		t.Fatal("parsed no capabilities out of the generator")
	}
	// CAP_CHOWN is for the helper's own socket, not an op.
	delete(granted, "CAP_CHOWN")
	// CAP_DAC_READ_SEARCH covers file reads across many ops; it fails
	// loudly (EACCES) rather than silently, so it is deliberately not
	// in RequiredCap.
	delete(granted, "CAP_DAC_READ_SEARCH")

	used := map[string]bool{}
	for _, c := range RequiredCap {
		used[c] = true
	}
	for c := range granted {
		if !used[c] {
			t.Errorf("generator grants %s but no op declares needing it; either "+
				"an op is missing from RequiredCap or the grant is unnecessary "+
				"privilege in a root process", c)
		}
	}
}
