// Command forbidden is the project's custom forbidden-call linter
// (REQ 10.2). It rejects:
//
//   - import "os/exec"             (any alias including dot / underscore;
//                                   the import-line check fires before
//                                   any usage could matter)
//   - os.Create(...)               (always write-mode)
//   - os.OpenFile(...)             (may be write-mode; reviewer must
//                                   confirm read-only and add a
//                                   // forbidden:allow comment)
//   - os.StartProcess(...)         (fork+exec)
//   - syscall.ForkExec(...)
//   - syscall.Exec(...)            (replace-current-process exec)
//   - syscall.StartProcess(...)    (low-level fork+exec)
//   - golang.org/x/sys/unix.Exec(...)  (same as syscall.Exec)
//
// from every package under daemon/internal/ EXCEPT the two
// chokepoints that the design (§7.4) names as the sole permitted
// sites: daemon/internal/daemon/helperinvoke/ and
// daemon/internal/helper/exec/.
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
	"sort"
	"strings"
)

type finding struct {
	Path    string
	Pos     token.Position
	Symbol  string
	Reason  string
}

func main() {
	root := flag.String("root", "daemon", "path to scan (recursive)")
	flag.Parse()

	allowed := map[string]bool{
		"daemon/internal/daemon/helperinvoke": true,
		"daemon/internal/helper/exec":         true,
	}

	fset := token.NewFileSet()
	var findings []finding

	err := filepath.WalkDir(*root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// Skip the chokepoint packages.
		dir := filepath.ToSlash(filepath.Dir(path))
		if allowed[dir] {
			return nil
		}

		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			fmt.Fprintf(os.Stderr, "forbidden: parse %s: %v\n", path, err)
			return nil
		}
		findings = append(findings, scanFile(fset, file, path)...)
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "forbidden: walk:", err)
		os.Exit(2)
	}

	if len(findings) == 0 {
		return
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		return findings[i].Pos.Offset < findings[j].Pos.Offset
	})
	for _, f := range findings {
		fmt.Fprintf(os.Stderr, "%s:%d:%d: forbidden %s (%s)\n",
			f.Pos.Filename, f.Pos.Line, f.Pos.Column, f.Symbol, f.Reason)
	}
	os.Exit(1)
}

func scanFile(fset *token.FileSet, file *ast.File, path string) []finding {
	var out []finding

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
		switch ip {
		case "os/exec":
			out = append(out, finding{
				Path:   path,
				Pos:    fset.Position(imp.Pos()),
				Symbol: `import "os/exec"`,
				Reason: "only daemon/internal/daemon/helperinvoke/ and daemon/internal/helper/exec/ may import os/exec (design §7.4)",
			})
		}
	}

	// Walk for selector expressions: os.Create, os.OpenFile,
	// syscall.ForkExec.
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		pkgPath := importedAs[ident.Name]
		switch {
		case pkgPath == "os" && sel.Sel.Name == "Create":
			out = append(out, finding{
				Path:   path,
				Pos:    fset.Position(sel.Pos()),
				Symbol: "os.Create",
				Reason: "always write-mode; route writes through the daemon's state dir API",
			})
		case pkgPath == "os" && sel.Sel.Name == "OpenFile":
			out = append(out, finding{
				Path:   path,
				Pos:    fset.Position(sel.Pos()),
				Symbol: "os.OpenFile",
				Reason: "may be write-mode; reviewer must confirm read-only and add a // forbidden:allow comment with justification",
			})
		case pkgPath == "os" && sel.Sel.Name == "StartProcess":
			out = append(out, finding{
				Path:   path,
				Pos:    fset.Position(sel.Pos()),
				Symbol: "os.StartProcess",
				Reason: "fork+exec; only the helper exec chokepoint may spawn processes",
			})
		case pkgPath == "syscall" && sel.Sel.Name == "ForkExec":
			out = append(out, finding{
				Path:   path,
				Pos:    fset.Position(sel.Pos()),
				Symbol: "syscall.ForkExec",
				Reason: "only the helper exec chokepoint may fork",
			})
		case pkgPath == "syscall" && sel.Sel.Name == "Exec":
			out = append(out, finding{
				Path:   path,
				Pos:    fset.Position(sel.Pos()),
				Symbol: "syscall.Exec",
				Reason: "replaces the current process; never permitted",
			})
		case pkgPath == "syscall" && sel.Sel.Name == "StartProcess":
			out = append(out, finding{
				Path:   path,
				Pos:    fset.Position(sel.Pos()),
				Symbol: "syscall.StartProcess",
				Reason: "low-level fork+exec; only the helper exec chokepoint may spawn processes",
			})
		case pkgPath == "golang.org/x/sys/unix" && sel.Sel.Name == "Exec":
			out = append(out, finding{
				Path:   path,
				Pos:    fset.Position(sel.Pos()),
				Symbol: "unix.Exec",
				Reason: "x/sys/unix variant of syscall.Exec; never permitted",
			})
		}
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

func buildCommentMap(file *ast.File, fset *token.FileSet) map[int]bool {
	out := map[int]bool{}
	for _, cg := range file.Comments {
		for _, c := range cg.List {
			if strings.Contains(c.Text, "forbidden:allow") {
				out[fset.Position(c.Slash).Line] = true
			}
		}
	}
	return out
}
