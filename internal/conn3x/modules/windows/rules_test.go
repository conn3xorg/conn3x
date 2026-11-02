// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// goFiles parses the non-test Go files under the given directories.
func goFiles(t *testing.T, dirs ...string) map[string]*ast.File {
	t.Helper()
	out := map[string]*ast.File{}
	fset := token.NewFileSet()
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err == nil {
				out[p] = f
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func pkgCall(n ast.Node) (pkg, fn string, call *ast.CallExpr) {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return "", "", nil
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", "", call
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", sel.Sel.Name, call
	}
	return id.Name, sel.Sel.Name, call
}

// A script reaches PowerShell only as script("a literal name"), so no Sprintf,
// + or Quote can have built it; apply scripts run only from Apply* functions.
func TestScriptsAreOnlyEmbeddedFiles(t *testing.T) {
	for path, f := range goFiles(t, ".") {
		if strings.HasPrefix(path, "ps"+string(filepath.Separator)) || strings.HasPrefix(path, "testdata") {
			continue
		}
		for _, imp := range f.Imports {
			if strings.HasSuffix(imp.Path.Value, `/transport/ssh"`) {
				t.Errorf("%s imports the ssh package: Windows modules have no use for Quote or Run", path)
			}
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fd, func(n ast.Node) bool {
				pkg, fn, call := pkgCall(n)
				if call == nil {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "script" {
					name, ok := call.Args[0].(*ast.BasicLit)
					if !ok {
						t.Errorf("%s: %s: script() needs a literal name", path, fd.Name.Name)
						return true
					}
					file, _ := strconv.Unquote(name.Value)
					if _, err := scripts.ReadFile(file); err != nil {
						t.Errorf("%s: %s: %v", path, fd.Name.Name, err)
					}
				}
				if pkg != "ps" {
					return true
				}
				switch fn {
				case "Read", "Apply":
					if fn == "Apply" && !strings.HasPrefix(fd.Name.Name, "Apply") {
						t.Errorf("%s: ps.Apply called from %s, not an Apply* function", path, fd.Name.Name)
					}
					inner, ok := call.Args[2].(*ast.CallExpr)
					if ok {
						if id, ok := inner.Fun.(*ast.Ident); ok && id.Name == "script" {
							return true
						}
					}
					if id, ok := call.Args[2].(*ast.Ident); ok && id.Name == "s" && fd.Name.Name == "readBool" {
						return true // its callers are checked by the script() rule above
					}
					t.Errorf("%s: %s: ps.%s must take script(\"...\")", path, fd.Name.Name, fn)
				case "User":
					if fd.Name.Name != "RunScript" && fd.Name.Name != "Satisfied" {
						t.Errorf("%s: ps.User called from %s: it is for a user's own script", path, fd.Name.Name)
					}
				}
				return true
			})
		}
	}
}

// Only the ps package may run anything raw on a Windows host.
func TestOnlyPsCallsRunRaw(t *testing.T) {
	for path, f := range goFiles(t, ".", "../../provider") {
		if strings.HasPrefix(path, "ps"+string(filepath.Separator)) {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "RunRaw" {
				t.Errorf("%s calls RunRaw; go through the ps package", path)
			}
			return true
		})
	}
}

// The same text rules scripts/ps-rules.ps1 checks with the real parser, so a
// machine without pwsh still catches the worst.
func TestScriptText(t *testing.T) {
	files, err := filepath.Glob("*.ps1")
	if err != nil || len(files) == 0 {
		t.Fatalf("no scripts: %v", err)
	}
	banned := map[string]*regexp.Regexp{
		"$Args":                 regexp.MustCompile(`(?i)\$args\b`),
		"Invoke-Expression":     regexp.MustCompile(`(?i)\b(invoke-expression|iex)\b`),
		"[scriptblock]::Create": regexp.MustCompile(`(?i)\[scriptblock\]::create`),
		"-Path":                 regexp.MustCompile(`(?i)\s-path\b`),
	}
	for _, name := range files {
		if !strings.HasPrefix(name, "read_") && !strings.HasPrefix(name, "apply_") {
			t.Errorf("%s is named neither read_* nor apply_*", name)
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for what, re := range banned {
			if re.Match(b) {
				t.Errorf("%s uses %s", name, what)
			}
		}
		if !strings.HasPrefix(string(b), "param($A)") {
			t.Errorf("%s must start with param($A)", name)
		}
	}
}
