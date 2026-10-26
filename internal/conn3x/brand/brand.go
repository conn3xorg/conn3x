// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package brand makes the conn3x binary speak as Conn3x without editing the
// upstream OpenTofu sources. Generate writes rewritten copies of the files
// whose string literals name OpenTofu or a tofu command, plus a go build
// overlay that swaps them in. Comments, identifiers, file extensions and
// environment variable names are left alone. The overlay also leaves out
// the remote-state backends in prunedBackends, and applies the few code
// patches in patches.
package brand

import (
	"encoding/json"
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

// commandPattern matches "tofu" used as the CLI name: followed by a
// subcommand, a flag, a usage bracket or a %s standing in for a subcommand.
// ".tofu", "tofu.rc" and a bare "tofu" don't match.
var commandPattern = regexp.MustCompile(`(^|[^\w.\-/])tofu( (?:\[|-|%s|init|plan|apply|destroy|validate|fmt|console|show|state|import|output|providers|refresh|taint|untaint|workspace|graph|login|logout|get|force-unlock|test|metadata|version|modules)\b)`)

func rewriteLiteral(lit string) string {
	lit = strings.ReplaceAll(lit, "OpenTofu", "Conn3x")
	return commandPattern.ReplaceAllString(lit, "${1}conn3x$2")
}

// rewriteSource rewrites the string literals in one Go source file.
func rewriteSource(src []byte) ([]byte, bool, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "", src, parser.SkipObjectResolution)
	if err != nil {
		return nil, false, err
	}
	type edit struct {
		start, end int
		text       string
	}
	var edits []edit
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if repl := rewriteLiteral(lit.Value); repl != lit.Value {
			start := fset.Position(lit.Pos()).Offset
			edits = append(edits, edit{start, start + len(lit.Value), repl})
		}
		return true
	})
	if len(edits) == 0 {
		return src, false, nil
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	out := append([]byte(nil), src...)
	for _, e := range edits {
		out = append(out[:e.start], append([]byte(e.text), out[e.end:]...)...)
	}
	return out, true, nil
}

// Generate rewrites the upstream sources under root into outDir and
// returns the path of the overlay file to pass to go build -overlay.
func Generate(root, outDir string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	outDir, err = filepath.Abs(outDir)
	if err != nil {
		return "", err
	}
	skip := map[string]bool{
		filepath.Join(root, "internal", "conn3x"): true,
		filepath.Join(root, "cmd", "conn3x"):      true,
		filepath.Join(root, "cmd", "tofu"):        true,
	}
	replace := map[string]string{}
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if skip[path] || d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			out, changed, err := rewriteSource(src)
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			if !changed {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			dest := filepath.Join(outDir, rel)
			if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(dest, out, 0o644); err != nil {
				return err
			}
			replace[path] = dest
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	if err := prune(root, outDir, replace); err != nil {
		return "", err
	}
	if err := patch(root, outDir, replace); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(struct{ Replace map[string]string }{replace}, "", "  ")
	if err != nil {
		return "", err
	}
	overlay := filepath.Join(outDir, "overlay.json")
	return overlay, os.WriteFile(overlay, data, 0o644)
}
