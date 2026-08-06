package main

import (
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scan parses src under the given filename and returns the findings
// production scanFile produces for it. filename matters: the _test.go
// suffix selects the narrower rule set.
func scan(t *testing.T, filename, src string) []finding {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parseFile(fset, filename, src)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	return scanFile(fset, f, filename)
}

func symbols(fs []finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Symbol)
	}
	return out
}

func TestScanFile(t *testing.T) {
	cases := []struct {
		name     string
		filename string
		src      string
		want     []string
	}{
		{
			name:     "write call in production code is rejected",
			filename: "a.go",
			src: `package p
import "os"
func f() { os.WriteFile("/etc/cron.d/x", nil, 0o644) }`,
			want: []string{"os.WriteFile"},
		},
		{
			// The regression the audit named explicitly: os.WriteFile
			// is the most idiomatic write call in modern Go and the
			// original seven-entry table did not list it.
			name:     "every filesystem mutator in the table is rejected",
			filename: "a.go",
			src: `package p
import "os"
func f() {
	os.Remove("x")
	os.RemoveAll("x")
	os.Rename("x", "y")
	os.Chmod("x", 0o600)
	os.Chown("x", 0, 0)
	os.Symlink("x", "y")
	os.MkdirAll("x", 0o755)
	os.Truncate("x", 0)
}`,
			want: []string{
				"os.Remove", "os.RemoveAll", "os.Rename", "os.Chmod",
				"os.Chown", "os.Symlink", "os.MkdirAll", "os.Truncate",
			},
		},
		{
			// Fixture writes into t.TempDir() are correct and
			// unavoidable; the shipped binary contains no _test.go.
			name:     "filesystem writes are permitted in test files",
			filename: "a_test.go",
			src: `package p
import "os"
func f() { os.WriteFile("fixture", nil, 0o644) }`,
			want: nil,
		},
		{
			// A test that shells out or signals is exactly what the
			// chokepoint rule exists to keep out, so these stay
			// forbidden regardless of file suffix.
			name:     "process and system-state calls stay forbidden in test files",
			filename: "a_test.go",
			src: `package p
import (
	"os"
	"syscall"
)
func f() {
	os.StartProcess("/bin/sh", nil, nil)
	syscall.Kill(1, 9)
	syscall.Reboot(0)
	os.Setenv("PATH", "/tmp")
}`,
			want: []string{"os.StartProcess", "syscall.Kill", "syscall.Reboot", "os.Setenv"},
		},
		{
			name:     "os/exec import is rejected",
			filename: "a.go",
			src: `package p
import "os/exec"
var _ = exec.Command`,
			want: []string{`import "os/exec"`},
		},
		{
			name:     "underscore-aliased os/exec import is rejected",
			filename: "a.go",
			src: `package p
import _ "os/exec"`,
			want: []string{`import "os/exec"`},
		},
		{
			// A bare Create(...) after a dot-import is an *ast.Ident,
			// not an *ast.SelectorExpr, so the selector walk never
			// sees it. The import is banned instead.
			name:     "dot-import of os is rejected",
			filename: "a.go",
			src: `package p
import . "os"
func f() { Create("/tmp/x") }`,
			want: []string{`dot-import "os"`},
		},
		{
			name:     "dot-import of syscall is rejected",
			filename: "a.go",
			src: `package p
import . "syscall"
func f() { Kill(1, 9) }`,
			want: []string{`dot-import "syscall"`},
		},
		{
			name:     "a non-default import alias still resolves",
			filename: "a.go",
			src: `package p
import goos "os"
func f() { goos.WriteFile("x", nil, 0o644) }`,
			want: []string{"os.WriteFile"},
		},
		{
			name:     "read-only calls are not rejected",
			filename: "a.go",
			src: `package p
import "os"
func f() {
	os.ReadFile("/proc/stat")
	os.Open("/proc/stat")
	os.Stat("/proc/stat")
	os.ReadDir("/proc")
}`,
			want: nil,
		},
		{
			name:     "a same-named method on an unrelated receiver is not rejected",
			filename: "a.go",
			src: `package p
type conn struct{}
func (conn) Chmod(string, uint32) {}
var os2 conn
func f() { os2.Chmod("x", 0) }`,
			want: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := symbols(scan(t, tc.filename, tc.src))
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("finding %d: got %q, want %q\nall: %v", i, got[i], tc.want[i], got)
				}
			}
		})
	}
}

func TestSuppression(t *testing.T) {
	cases := []struct {
		name       string
		src        string
		suppressed bool
	}{
		{
			name: "trailing directive on the call line suppresses",
			src: `package p
import "os"
func f() { os.Remove("x") } // forbidden:allow own socket
`,
			suppressed: true,
		},
		{
			name: "directive on the line above suppresses",
			src: `package p
import "os"
func f() {
	// forbidden:allow own socket
	os.Remove("x")
}`,
			suppressed: true,
		},
		{
			// The justification is the point of the directive, so it
			// has to be allowed to wrap. Matching only Pos.Line-1
			// would exempt nothing here.
			name: "a multi-line justification block suppresses the call after it",
			src: `package p
import "os"
func f() {
	// forbidden:allow the helper's own listening socket under its
	// systemd RuntimeDirectory=; a stale file from an unclean stop
	// makes bind fail. Not a health-check code path.
	os.Remove("x")
}`,
			suppressed: true,
		},
		{
			// The audit's C-1 complaint: substring-matching the token
			// meant any comment merely mentioning it disabled every
			// finding on that line, including this file's own prose.
			name: "a comment merely mentioning the token does not suppress",
			src: `package p
import "os"
func f() {
	// see the forbidden:allow policy in design-overview.md
	os.Remove("x")
}`,
			suppressed: false,
		},
		{
			name: "a directive two lines above does not reach the call",
			src: `package p
import "os"
func f() {
	// forbidden:allow

	os.Remove("x")
}`,
			suppressed: false,
		},
		{
			name: "block-comment form suppresses",
			src: `package p
import "os"
func f() {
	/* forbidden:allow own socket */
	os.Remove("x")
}`,
			suppressed: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scan(t, "a.go", tc.src)
			if tc.suppressed && len(got) != 0 {
				t.Fatalf("expected suppression, got %v", symbols(got))
			}
			if !tc.suppressed && len(got) == 0 {
				t.Fatal("expected a finding, got none")
			}
		})
	}
}

// The package doc and the rule table both spell the directive out in
// prose. Under the old substring match those very comments suppressed
// every finding on their own line; the anchored form must not.
func TestSuppressionIsAnchored(t *testing.T) {
	for _, s := range []string{
		"// see the forbidden:allow policy",
		"// a `// forbidden:allow` comment carrying a justification",
		"// reviewer must add a // forbidden:allow comment",
	} {
		if suppression.MatchString(s) {
			t.Errorf("prose mention should not be a directive: %q", s)
		}
	}
	for _, s := range []string{
		"// forbidden:allow own socket",
		"//forbidden:allow own socket",
		"/* forbidden:allow own socket */",
	} {
		if !suppression.MatchString(s) {
			t.Errorf("should be a directive: %q", s)
		}
	}
}

// A file the linter cannot parse must produce a finding. Returning nil
// left the exit code at 0, and under `set -euo pipefail` in build.sh a
// zero exit is a green release built on a file that was never read.
func TestParseErrorFailsClosed(t *testing.T) {
	fset := token.NewFileSet()
	_, err := parseFile(fset, "broken.go", "package p\nfunc f( {")
	if err == nil {
		t.Fatal("fixture should not parse")
	}
	f := parseErrorFinding("broken.go", err)
	if f.Symbol != "parse error" {
		t.Errorf("Symbol = %q, want %q", f.Symbol, "parse error")
	}
	if !strings.Contains(f.Reason, "cannot verify") {
		t.Errorf("Reason = %q, want it to say the file could not be verified", f.Reason)
	}
}

// M-4: syscall.Open + syscall.Write reconstructs os.WriteFile in two
// calls, and syscall.Syscall reconstructs anything. Omitting the
// primitives would leave the rest of the table decorative.
func TestLowLevelPrimitivesAreCovered(t *testing.T) {
	src := `package p
import "syscall"
func f() {
	fd, _ := syscall.Open("/etc/cron.d/y", syscall.O_WRONLY|syscall.O_CREAT, 0644)
	syscall.Write(fd, nil)
	syscall.Ftruncate(fd, 0)
	syscall.Fchmod(fd, 0777)
	syscall.Fchown(fd, 0, 0)
	syscall.Setresuid(0, 0, 0)
	syscall.Setgroups(nil)
	syscall.Syscall(0, 0, 0, 0)
	syscall.RawSyscall(0, 0, 0, 0)
	syscall.Chroot("/")
	syscall.Setns(0, 0)
}`
	got := symbols(scan(t, "a.go", src))
	want := []string{
		"syscall.Open", "syscall.Write", "syscall.Ftruncate", "syscall.Fchmod",
		"syscall.Fchown", "syscall.Setresuid", "syscall.Setgroups",
		"syscall.Syscall", "syscall.RawSyscall", "syscall.Chroot", "syscall.Setns",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v (%d), want %d findings", got, len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("finding %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

// The syscall and x/sys/unix tables must not drift apart: a symbol
// guarded in one and not the other is a bypass by import swap.
func TestSyscallAndUnixTablesAgree(t *testing.T) {
	sys := forbiddenCalls["syscall"]
	unix := forbiddenCalls["golang.org/x/sys/unix"]
	// Symbols legitimately in only one package.
	only := map[string]bool{
		"StartProcess": true, // syscall only
		"Pivotroot":    true, // unix only
		"Fsopen":       true, // unix only
		"Fsmount":      true, // unix only
	}
	for name := range sys {
		if !only[name] && unix[name].Reason == "" {
			t.Errorf("%q guarded in syscall but not in x/sys/unix", name)
		}
	}
	for name := range unix {
		if !only[name] && sys[name].Reason == "" {
			t.Errorf("%q guarded in x/sys/unix but not in syscall", name)
		}
	}
}

// Raw syscalls bypass every selector check, so they stay forbidden in
// test files too.
func TestRawSyscallsAreForbiddenInTests(t *testing.T) {
	src := `package p
import "syscall"
func f() { syscall.Syscall(0, 0, 0, 0) }`
	if got := symbols(scan(t, "a_test.go", src)); len(got) != 1 {
		t.Errorf("got %v, want syscall.Syscall reported in a _test.go file", got)
	}
}

// os.Open is read-only and must stay permitted; syscall.Open takes a
// mode and must not.
func TestOsOpenPermittedSyscallOpenNot(t *testing.T) {
	if got := symbols(scan(t, "a.go", "package p\nimport \"os\"\nfunc f() { os.Open(\"/proc/stat\") }")); len(got) != 0 {
		t.Errorf("os.Open should be permitted, got %v", got)
	}
	if got := symbols(scan(t, "a.go", "package p\nimport \"syscall\"\nfunc f() { syscall.Open(\"/x\", 0, 0) }")); len(got) != 1 {
		t.Errorf("syscall.Open should be forbidden, got %v", got)
	}
}

// M-3: WalkDir calls back on the root itself first, so skipping any
// directory whose name starts with "." terminated the entire walk —
// `-root .` exited 0 having read no files. Reproduced here with a root
// whose base name starts with a dot, which hits the same branch
// without any process-global chdir. The end-to-end seam (walk + parse
// + finding) had no coverage; parseErrorFinding was tested in
// isolation, which is exactly where the gap was.
func TestWalkCoversTheRootItself(t *testing.T) {
	for _, rootName := range []string{".", ".hidden", "vendor", "plain"} {
		t.Run(rootName, func(t *testing.T) {
			base := t.TempDir()
			root := filepath.Join(base, rootName)
			sub := filepath.Join(root, "internal", "tools")
			if err := os.MkdirAll(sub, 0o755); err != nil {
				t.Fatal(err)
			}
			src := "package x\n\nimport \"os\"\n\nfunc f() { os.WriteFile(\"/etc/cron.d/x\", nil, 0o644) }\n"
			if err := os.WriteFile(filepath.Join(sub, "x.go"), []byte(src), 0o600); err != nil {
				t.Fatal(err)
			}
			// A file the linter cannot parse must be reported, not skipped.
			if err := os.WriteFile(filepath.Join(sub, "broken.go"), []byte("package x\nfunc f( {"), 0o600); err != nil {
				t.Fatal(err)
			}

			got := walkRoot(root, map[string]bool{})
			if len(got) != 2 {
				var syms []string
				for _, f := range got {
					syms = append(syms, f.Symbol)
				}
				t.Errorf("root %q: got %v, want os.WriteFile and a parse error", rootName, syms)
			}
		})
	}
}

// A directory named "vendor" or starting with "." is still skipped when
// it is BELOW the root — only the root itself is unconditionally
// descended into.
func TestWalkSkipsHiddenAndVendorBelowTheRoot(t *testing.T) {
	root := t.TempDir()
	src := "package x\n\nimport \"os\"\n\nfunc f() { os.WriteFile(\"x\", nil, 0o644) }\n"
	for _, name := range []string{"vendor", ".git"} {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got := walkRoot(root, map[string]bool{}); len(got) != 0 {
		t.Errorf("vendor/ and .git/ below the root should be skipped, got %d findings", len(got))
	}
}

// A chokepoint package is exempt; everything else under the root is not.
func TestWalkSkipsChokepointPackages(t *testing.T) {
	root := t.TempDir()
	chokepoint := filepath.Join(root, "internal", "helper", "exec")
	if err := os.MkdirAll(chokepoint, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "package exec\n\nimport \"os\"\n\nfunc f() { os.WriteFile(\"x\", nil, 0o644) }\n"
	if err := os.WriteFile(filepath.Join(chokepoint, "e.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	key := filepath.ToSlash(chokepoint)

	if got := walkRoot(root, map[string]bool{key: true}); len(got) != 0 {
		t.Errorf("chokepoint package was scanned: %d findings", len(got))
	}
	if got := walkRoot(root, map[string]bool{}); len(got) != 1 {
		t.Errorf("without the exemption the call should be reported, got %d findings", len(got))
	}
}

// The chokepoint paths main() passes must match how walkRoot keys them,
// or the exemption silently stops applying and the build breaks on the
// helper's own socket management.
func TestChokepointKeysMatchTheRepoLayout(t *testing.T) {
	for _, want := range []string{
		"daemon/internal/daemon/helperinvoke",
		"daemon/internal/helper/exec",
		"daemon/cmd/capstemplate",
	} {
		if !chokepoints[want] {
			t.Errorf("chokepoints is missing %q", want)
		}
	}
}

// The exemption list is a security boundary, so it is pinned by size
// as well as by content: a fourth entry added without a matching
// change here means someone widened the read-only property's escape
// hatch without anyone reviewing the reason.
func TestChokepointsHasNoUnreviewedEntries(t *testing.T) {
	if len(chokepoints) != 3 {
		t.Errorf("chokepoints has %d entries, want 3: %v", len(chokepoints), chokepoints)
	}
}
