package workload

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// build/workload-tags is an INTERFACE: downstream packaging reads it
// to decide what to pass to `go build -tags`, and it does not read this
// source tree. Before it existed the list was hardcoded in build.sh and
// duplicated by hand downstream, so adding a plugin here produced a
// build without it — no error, no warning, just a probe that never
// appears in any response.
//
// A file nobody checks is not an interface, it is a second copy. This
// test is the check: the tags in the file must be exactly the //go:build
// tags on the plugin sources in this package.
func TestWorkloadTagsFileMatchesTheSources(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..", "..")

	declared := readTagFile(t, filepath.Join(root, "build", "workload-tags"))
	inSource := readBuildTags(t, ".")

	if len(declared) == 0 {
		t.Fatal("build/workload-tags declares no tags")
	}
	if strings.Join(declared, ",") != strings.Join(inSource, ",") {
		t.Errorf("build/workload-tags and the plugin sources disagree.\n"+
			"  file:    %v\n"+
			"  sources: %v\n"+
			"A tag present in the sources but missing from the file means the "+
			"downstream build silently omits that plugin.", declared, inSource)
	}
}

// Every declared tag must correspond to a plugin that actually
// registers, so the file cannot promise a probe that does not exist.
func TestEveryDeclaredTagHasARegisteringPlugin(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..", "..")
	for _, tag := range readTagFile(t, filepath.Join(root, "build", "workload-tags")) {
		src := findSourceForTag(t, ".", tag)
		if src == "" {
			t.Errorf("tag %q is declared but no source file carries that build tag", tag)
			continue
		}
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "Register(") {
			t.Errorf("%s carries tag %q but never calls Register", src, tag)
		}
	}
}

// The default build ships every declared plugin, so under the default
// tag set the registry must be exactly as long as the file.
func TestDefaultBuildRegistersEveryDeclaredPlugin(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..", "..")
	declared := readTagFile(t, filepath.Join(root, "build", "workload-tags"))

	got := len(CompiledIn())
	if got == 0 {
		t.Skip("built without workload tags; nothing to compare")
	}
	if got != len(declared) {
		t.Errorf("%d plugins registered, %d declared in build/workload-tags: %v",
			got, len(declared), declared)
	}
}

func readTagFile(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	sort.Strings(out)
	return out
}

var buildTagRE = regexp.MustCompile(`(?m)^//go:build\s+(wl_\w+)`)

func readBuildTags(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if m := buildTagRE.FindStringSubmatch(string(b)); m != nil {
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}

func findSourceForTag(t *testing.T, dir, tag string) string {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if m := buildTagRE.FindStringSubmatch(string(b)); m != nil && m[1] == tag {
			return p
		}
	}
	return ""
}
