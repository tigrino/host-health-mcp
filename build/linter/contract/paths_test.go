// Package contract holds build-time checks that are about the shape of
// the repository rather than the behaviour of any binary. They live in
// the linter module because that is where build-gating checks already
// run, and because a check that asserts "this path exists" has no
// business importing daemon or plugin code.
package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot walks up from the test's working directory to the checkout
// root. The anchor is doc/REQUIREMENTS.txt rather than README.md,
// because build/ has a README of its own and anchoring on the bare
// name stops one directory short.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "doc", "REQUIREMENTS.txt")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate the checkout root")
	return ""
}

// The paths a separate build system reads by name, per README section
// 9.1. Nothing in this repository breaks when one of them moves — the
// failure lands downstream, at package build or at install time on a
// host, which is why the check has to be here rather than implied by
// something else compiling.
var downstreamPaths = []struct {
	path string
	// why names the consequence of the path being absent, so a
	// failure explains itself without a trip to the README.
	why string
}{
	{"daemon", "both binaries are built from this module"},
	{"plugin", "the client binary is built from this module"},
	{"build/systemd/host-health-mcp.service", "installed as the daemon unit"},
	{"build/systemd/host-health-mcp-helper.service", "installed as the helper unit"},
	{"build/postinst/caps-template.sh", "invoked at dpkg configure time; its absence fails the install"},
	{"build/examples", "installed as the shipped example configs"},
	{"build/workload-tags", "read to derive `go build -tags`; its absence silently drops every workload probe"},
	{"doc", "installed as package documentation"},
}

func TestDownstreamPathsStillExist(t *testing.T) {
	root := repoRoot(t)
	for _, p := range downstreamPaths {
		if _, err := os.Stat(filepath.Join(root, p.path)); err != nil {
			t.Errorf("%s is missing or moved — %s. It is named in README "+
				"section 9.1 as an interface; relocating it needs a release "+
				"note, not a silent rename.", p.path, p.why)
		}
	}
}

// The README table is the document downstream reads. A path enforced
// here but absent there is an undocumented dependency; the reverse is
// a documented promise nothing checks.
func TestDownstreamPathsAreDocumented(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	// Scoped to the section, not the whole file: several of these paths
	// are mentioned in passing elsewhere in the README, and a passing
	// mention is not the table a downstream packager reads.
	readme := string(b)
	start := strings.Index(readme, "### 9.1 Paths that downstream packaging depends on")
	if start < 0 {
		t.Fatal("README section 9.1 is gone; the path contract has no home")
	}
	end := strings.Index(readme[start:], "\n## ")
	if end < 0 {
		t.Fatal("could not find the end of README section 9.1")
	}
	section := readme[start : start+end]
	for _, p := range downstreamPaths {
		if !strings.Contains(section, p.path) {
			t.Errorf("%s is enforced as a downstream dependency but never "+
				"named in README section 9.1", p.path)
		}
	}
}
