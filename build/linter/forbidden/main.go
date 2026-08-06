// Command forbidden is the project's custom forbidden-call linter
// (REQ 10.2). It enforces the read-only-by-construction property from
// design §7.4 by rejecting, from every package under the scanned root
// EXCEPT the two chokepoints the design names as the sole permitted
// sites (daemon/internal/daemon/helperinvoke/ and
// daemon/internal/helper/exec/):
//
//   - import "os/exec" under any alias, including dot and underscore;
//     the import-line check fires before any usage could matter.
//   - a dot-import of os, syscall, or golang.org/x/sys/unix — a bare
//     Create(...) after `import . "os"` parses as an *ast.Ident, not
//     an *ast.SelectorExpr, so it would walk straight past the
//     selector checks. Rejecting the import is cheaper than resolving
//     identifiers and costs nothing: the tree dot-imports nothing.
//   - every process-spawning and state-changing call in forbiddenCalls
//     below (see that table for the per-symbol reasons).
//
// A call site that is genuinely read-only despite matching (os.OpenFile
// with O_RDONLY being the usual case) is exempted with a
// `// forbidden:allow` comment carrying a justification, on the line
// of the call or the line above it.
//
// A third form of exemption exists for a package that legitimately
// needs a small, fixed set of these calls: narrowChokepoints names the
// package and the exact symbols it may use. Every other rule still
// applies to it. That is the right tool when the reason is
// package-wide but the permission should not be — see the comment on
// narrowChokepoints for why the distinction earned its own mechanism.
//
// The linter fails CLOSED: a file it cannot parse is reported as a
// finding, because "the enforcement mechanism could not read this
// file" must never be indistinguishable from "this file is clean".
//
// Known limits, so coverage is not inferred from the table alone:
//
//   - Matching is syntactic. A call through a value rather than an
//     import name — (*os.Process).Kill, an io.Writer that happens to
//     be a file, a function stored in a variable — is invisible here,
//     because sel.X is an *ast.Ident bound to a variable and the
//     import lookup misses. Catching those needs type information.
//   - Only the root passed to -root is scanned. build.sh invokes it
//     once per module root (daemon and plugin).
//
// Stdlib-only; runs from build/build.sh.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type finding struct {
	Path   string
	Pos    token.Position
	Symbol string
	Reason string
}

// rule is one forbidden selector.
type rule struct {
	// Reason is printed with the finding.
	Reason string
	// TestsToo marks a call that is forbidden in _test.go files as
	// well. Process spawning, signalling, and system-state changes
	// (mount, reboot, ptrace, credential changes) are never legitimate
	// in this tree, test or not — a test that shells out is exactly
	// the thing design §7.4 exists to keep out.
	//
	// Filesystem writes are different in kind: a table-driven parser
	// test writes its fixture into t.TempDir(), which is both correct
	// and unavoidable. Those are scanned in non-test files only. The
	// read-only property (REQ 6.1) is a property of the shipped
	// binary, and _test.go files are not compiled into it.
	//
	// This split is a review aid, not a security boundary: build.sh
	// runs `go test` BEFORE the linter, so for test files this tool is
	// detection after execution and never prevention. A hostile test
	// file has already run by the time any of these rules fire,
	// wherever the line is drawn.
	TestsToo bool
}

// forbiddenCalls maps import-path + selector to its rule. Anything
// that creates, writes, renames, unlinks, or re-permissions a
// filesystem object, spawns a process, or signals one belongs here:
// the daemon's read-only property (REQ 6.1) is stated as a property
// of the binary, and this table is what makes that statement
// checkable rather than aspirational.
//
// The systemd hardening (ProtectSystem=strict, ReadWritePaths=,
// empty CapabilityBoundingSet, SystemCallFilter=) is a real backstop
// but not a substitute: it is thinner on the helper, which runs as
// root with a writable /run/host-health-mcp.
var forbiddenCalls = map[string]map[string]rule{
	"os": {
		"Create":       {Reason: "always write-mode; route writes through the daemon's state dir API"},
		"CreateTemp":   {Reason: "creates and writes a file"},
		"OpenFile":     {Reason: "may be write-mode; reviewer must confirm read-only and add a // forbidden:allow comment with justification"},
		"WriteFile":    {Reason: "writes a file"},
		"Remove":       {Reason: "unlinks a filesystem object"},
		"RemoveAll":    {Reason: "unlinks a filesystem subtree"},
		"Rename":       {Reason: "moves a filesystem object"},
		"Truncate":     {Reason: "changes file length"},
		"Mkdir":        {Reason: "creates a directory"},
		"MkdirAll":     {Reason: "creates a directory tree"},
		"MkdirTemp":    {Reason: "creates a directory"},
		"Chmod":        {Reason: "changes file mode"},
		"Chown":        {Reason: "changes file ownership"},
		"Lchown":       {Reason: "changes file ownership"},
		"Chtimes":      {Reason: "changes file timestamps"},
		"Symlink":      {Reason: "creates a symlink"},
		"Link":         {Reason: "creates a hard link"},
		"Chdir":        {Reason: "changes process working directory", TestsToo: true},
		"Setenv":       {Reason: "mutates process environment", TestsToo: true},
		"Unsetenv":     {Reason: "mutates process environment", TestsToo: true},
		"StartProcess": {Reason: "fork+exec; only the helper exec chokepoint may spawn processes", TestsToo: true},
	},
	// The syscall and unix tables must stay in step with each other and
	// with the os table above. The primitives matter more than the
	// convenience wrappers: syscall.Open + syscall.Write reconstructs
	// os.WriteFile in two calls, and syscall.Syscall reconstructs any
	// of them, so omitting those three would leave the rest of this
	// table decorative. Note os.Open IS deliberately absent (read-only)
	// while syscall.Open is present — the latter takes a mode argument
	// and is not equivalent.
	"syscall": syscallRules,
	// x/sys/unix mirrors syscall with a wider *at surface.
	"golang.org/x/sys/unix": unixRules,
}

// lowLevel is the set shared by syscall and x/sys/unix: the raw
// primitives plus the credential and namespace calls.
var lowLevel = map[string]rule{
	"Open":       {Reason: "takes a mode and can create/truncate; use os.Open for read-only access"},
	"Openat":     {Reason: "takes a mode and can create/truncate"},
	"Openat2":    {Reason: "takes a mode and can create/truncate"},
	"Creat":      {Reason: "creates a file"},
	"Write":      {Reason: "writes to a descriptor"},
	"Pwrite":     {Reason: "writes to a descriptor"},
	"Syscall":    {Reason: "raw syscall; bypasses every check in this table", TestsToo: true},
	"Syscall6":   {Reason: "raw syscall; bypasses every check in this table", TestsToo: true},
	"RawSyscall": {Reason: "raw syscall; bypasses every check in this table", TestsToo: true},

	"ForkExec":  {Reason: "only the helper exec chokepoint may fork", TestsToo: true},
	"Exec":      {Reason: "replaces the current process; never permitted", TestsToo: true},
	"Kill":      {Reason: "signals a process; the daemon never changes system state", TestsToo: true},
	"Tgkill":    {Reason: "signals a thread", TestsToo: true},
	"Ptrace":    {Reason: "attaches to another process", TestsToo: true},
	"Mount":     {Reason: "changes system state", TestsToo: true},
	"Unmount":   {Reason: "changes system state", TestsToo: true},
	"Reboot":    {Reason: "changes system state", TestsToo: true},
	"Chroot":    {Reason: "changes the process root", TestsToo: true},
	"Setns":     {Reason: "joins another namespace", TestsToo: true},
	"Setuid":    {Reason: "changes process credentials", TestsToo: true},
	"Setgid":    {Reason: "changes process credentials", TestsToo: true},
	"Setreuid":  {Reason: "changes process credentials", TestsToo: true},
	"Setregid":  {Reason: "changes process credentials", TestsToo: true},
	"Setgroups": {Reason: "changes process credentials", TestsToo: true},

	"Unlink":    {Reason: "unlinks a filesystem object"},
	"Unlinkat":  {Reason: "unlinks a filesystem object"},
	"Rename":    {Reason: "moves a filesystem object"},
	"Renameat":  {Reason: "moves a filesystem object"},
	"Mkdir":     {Reason: "creates a directory"},
	"Mkdirat":   {Reason: "creates a directory"},
	"Rmdir":     {Reason: "removes a directory"},
	"Chmod":     {Reason: "changes file mode"},
	"Fchmod":    {Reason: "changes file mode"},
	"Fchmodat":  {Reason: "changes file mode"},
	"Chown":     {Reason: "changes file ownership"},
	"Fchown":    {Reason: "changes file ownership"},
	"Fchownat":  {Reason: "changes file ownership"},
	"Lchown":    {Reason: "changes file ownership"},
	"Symlink":   {Reason: "creates a symlink"},
	"Symlinkat": {Reason: "creates a symlink"},
	"Link":      {Reason: "creates a hard link"},
	"Linkat":    {Reason: "creates a hard link"},
	"Truncate":  {Reason: "changes file length"},
	"Ftruncate": {Reason: "changes file length"},
}

var syscallRules = withExtra(lowLevel, map[string]rule{
	"StartProcess": {Reason: "low-level fork+exec; only the helper exec chokepoint may spawn processes", TestsToo: true},
	"Setresuid":    {Reason: "changes process credentials", TestsToo: true},
	"Setresgid":    {Reason: "changes process credentials", TestsToo: true},
})

var unixRules = withExtra(lowLevel, map[string]rule{
	"Setresuid": {Reason: "changes process credentials", TestsToo: true},
	"Setresgid": {Reason: "changes process credentials", TestsToo: true},
	"Pivotroot": {Reason: "changes the process root", TestsToo: true},
	"Fsopen":    {Reason: "changes system state", TestsToo: true},
	"Fsmount":   {Reason: "changes system state", TestsToo: true},
})

func withExtra(base, extra map[string]rule) map[string]rule {
	out := make(map[string]rule, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// dotImportBanned lists the import paths that may not be dot-imported.
// See the package comment for why this is a ban rather than a
// resolution problem to solve.
var dotImportBanned = map[string]bool{
	"os":                    true,
	"syscall":               true,
	"golang.org/x/sys/unix": true,
	"os/exec":               true,
}

// chokepoints are the only packages design §7.4 permits to hold the
// calls in forbiddenCalls. Exemption here is total: every rule in the
// table is lifted for the whole package. Two entries, both of them
// process-execution sites — the daemon's socket client to the helper,
// and the helper's sole os/exec site.
//
// Adding a third entry means deciding that some package may spawn
// processes, signal them, and mutate the filesystem, all unreviewed.
// That is almost never what is wanted; see narrowChokepoints.
var chokepoints = map[string]bool{
	"daemon/internal/daemon/helperinvoke": true,
	"daemon/internal/helper/exec":         true,
}

// narrowChokepoints permit a package a NAMED set of calls and nothing
// else. Every other rule in the table still applies, so a package here
// remains unable to spawn a process, signal one, or change system
// state without the build failing.
//
// This exists because 2.4.0 briefly got it wrong. The capability
// generator legitimately writes two systemd drop-ins, so it was added
// to chokepoints above — which also, silently, lifted the
// process-spawning rules for it. The generator spawns nothing, so
// nothing was exploitable; what was lost was the guarantee that it
// never would. threat-model.md asserts that only the two packages
// above may exec, and a package-level exemption made that assertion
// false rather than merely unenforced.
//
// Naming the calls keeps the boundary in one place — the argument for
// a chokepoint over scattered // forbidden:allow comments — without
// the all-or-nothing granularity that made the first attempt wrong.
// A Symbol matches the finding's own Symbol field: "os.WriteFile",
// or `import "os/exec"` for the import check.
var narrowChokepoints = map[string]map[string]bool{
	// The install-time capability generator. Not the daemon, not the
	// helper, never in the request path: a one-shot binary the
	// postinst runs to write the helper's CapabilityBoundingSet
	// drop-in and the daemon's optional IPAddressAllow drop-in.
	// Writing those two files is its entire purpose.
	"daemon/cmd/capstemplate": {
		"os.MkdirAll":  true, // create the drop-in directory
		"os.WriteFile": true, // write caps.conf / 10-ip-filter.conf
		"os.Remove":    true, // retire the obsolete 10-ip-egress.conf
	},
}

// walkRoot scans every .go file under root except those in allowed,
// and returns the findings. A file that will not parse yields a
// finding rather than being skipped. Separated from main so the walk,
// which is where the fail-open bug lived, is reachable from a test.
func walkRoot(root string, allowed map[string]bool, narrow map[string]map[string]bool) []finding {
	fset := token.NewFileSet()
	var findings []finding

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// WalkDir calls back on the root itself first. Skipping it
			// on a name test terminates the whole walk and returns no
			// findings — so `-root .` used to report a clean tree
			// without reading a single file, which is the exact
			// failure this linter must never have. The root is always
			// descended into.
			if path == root {
				return nil
			}
			if d.Name() == "vendor" || strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Skip the chokepoint packages.
		dir := filepath.ToSlash(filepath.Dir(path))
		if allowed[dir] {
			return nil
		}

		file, err := parseFile(fset, path, nil)
		if err != nil {
			findings = append(findings, parseErrorFinding(path, err))
			return nil
		}
		got := scanFile(fset, file, path)
		// A narrow chokepoint is scanned like anything else; only the
		// findings it names are dropped. Everything the package is not
		// permitted still fails the build.
		if permitted, ok := narrow[dir]; ok {
			kept := got[:0]
			for _, f := range got {
				if permitted[f.Symbol] {
					continue
				}
				kept = append(kept, f)
			}
			got = kept
		}
		findings = append(findings, got...)
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "forbidden: walk:", err)
		os.Exit(2)
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		return findings[i].Pos.Offset < findings[j].Pos.Offset
	})
	return findings
}

func main() {
	root := flag.String("root", "daemon", "path to scan (recursive)")
	flag.Parse()

	findings := walkRoot(*root, chokepoints, narrowChokepoints)

	if len(findings) == 0 {
		return
	}
	for _, f := range findings {
		fmt.Fprintf(os.Stderr, "%s:%d:%d: forbidden %s (%s)\n",
			f.Pos.Filename, f.Pos.Line, f.Pos.Column, f.Symbol, f.Reason)
	}
	os.Exit(1)
}

// parseFile is the linter's only parse entry point, so the mode flags
// are stated once and the tests exercise the same ones the scan does.
//
// ParseComments is load-bearing: without it file.Comments is empty and
// the // forbidden:allow suppression can never match anything. It was
// absent until 2.3.0, which went unnoticed only because the old
// seven-symbol table matched nothing in the tree, so no call site ever
// needed exempting.
func parseFile(fset *token.FileSet, path string, src any) (*ast.File, error) {
	return parser.ParseFile(fset, path, src, parser.SkipObjectResolution|parser.ParseComments)
}

// parseErrorFinding reports a file the linter could not read. Fail
// closed: returning no finding left the exit code at 0, and under
// `set -euo pipefail` in build.sh a zero exit is a green release built
// on a file the enforcement mechanism never looked at. "Could not
// verify" must never be indistinguishable from "clean".
func parseErrorFinding(path string, err error) finding {
	return finding{
		Path:   path,
		Pos:    token.Position{Filename: path},
		Symbol: "parse error",
		Reason: fmt.Sprintf("cannot verify this file: %v", err),
	}
}

func scanFile(fset *token.FileSet, file *ast.File, path string) []finding {
	var out []finding
	isTest := strings.HasSuffix(path, "_test.go")

	// Track imports.
	importedAs := map[string]string{} // local-name -> import-path
	for _, imp := range file.Imports {
		ip := strings.Trim(imp.Path.Value, `"`)
		name := ""
		if imp.Name != nil {
			name = imp.Name.Name
		} else {
			// Local binding defaults to the package's base name. For
			// "os/exec" that's "exec"; for "syscall" that's "syscall".
			name = filepath.Base(ip)
		}
		importedAs[name] = ip
		if ip == "os/exec" {
			out = append(out, finding{
				Path:   path,
				Pos:    fset.Position(imp.Pos()),
				Symbol: `import "os/exec"`,
				Reason: "only daemon/internal/daemon/helperinvoke/ and daemon/internal/helper/exec/ may import os/exec (design §7.4)",
			})
		}
		if name == "." && dotImportBanned[ip] {
			out = append(out, finding{
				Path:   path,
				Pos:    fset.Position(imp.Pos()),
				Symbol: `dot-import "` + ip + `"`,
				Reason: "a dot-import hides the package qualifier from the selector checks below; import it normally",
			})
		}
	}

	// Walk for selector expressions against the forbiddenCalls table.
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		pkgPath, ok := importedAs[ident.Name]
		if !ok {
			return true
		}
		r, ok := forbiddenCalls[pkgPath][sel.Sel.Name]
		if !ok {
			return true
		}
		if isTest && !r.TestsToo {
			return true
		}
		out = append(out, finding{
			Path:   path,
			Pos:    fset.Position(sel.Pos()),
			Symbol: filepath.Base(pkgPath) + "." + sel.Sel.Name,
			Reason: r.Reason,
		})
		return true
	})

	// Filter out findings on lines with the // forbidden:allow
	// override. Keeps the noise level honest while preserving an
	// audit trail in the source.
	if len(out) == 0 {
		return out
	}
	commentMap := buildCommentMap(file, fset)
	kept := out[:0]
	for _, f := range out {
		if commentMap[f.Pos.Line] {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// suppression matches a comment whose directive is `forbidden:allow`
// at the start of its text, followed by a justification. Anchoring
// matters: substring-matching the token meant that a comment merely
// discussing forbidden:allow — including this package's own
// documentation — silently disabled every finding on that line.
var suppression = regexp.MustCompile(`^(//|/\*)\s*forbidden:allow\b`)

// buildCommentMap returns the set of source lines on which a finding
// is suppressed. A `// forbidden:allow` directive covers the line it
// sits on, every other line of its own comment group, and the line
// immediately after the group — so a justification long enough to
// wrap onto several lines still exempts the call it introduces.
func buildCommentMap(file *ast.File, fset *token.FileSet) map[int]bool {
	out := map[int]bool{}
	for _, cg := range file.Comments {
		found := false
		for _, c := range cg.List {
			if suppression.MatchString(c.Text) {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		start := fset.Position(cg.Pos()).Line
		end := fset.Position(cg.End()).Line
		for l := start; l <= end+1; l++ {
			out[l] = true
		}
	}
	return out
}
