// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package brand

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, src := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// Generate stops on anything that would leave the build half branded.
func TestGenerateFailures(t *testing.T) {
	for want, files := range map[string]map[string]string{
		// A tree without internal/ is not OpenTofu's.
		"no such file or directory": {"cmd/x.go": "package main\n"},
		"bad.go: ":                  {"internal/bad.go": "package x\nvar = \n"},
		backendInit + ": expected an import and a table entry": {"internal/backend/init/init.go": "package init\n", "cmd/main.go": "package main\n"},
		`internal/command/views/json_view.go: expected "fmt.Sprintf(\"Conn3x %s\", version)" once, found it 0 times`: {
			"internal/command/views/json_view.go": "package views\n", "cmd/main.go": "package main\n",
		},
	} {
		root := t.TempDir()
		writeTree(t, root, files)
		if _, err := Generate(root, t.TempDir()); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}

	// An output directory that can't be made is an error, not a skip.
	root := t.TempDir()
	writeTree(t, root, map[string]string{"internal/a.go": "package a\n\nvar s = \"OpenTofu\"\n", "cmd/main.go": "package main\n"})
	out := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(out, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(root, out); err == nil {
		t.Error("wrote into a file as if it were a directory")
	}
}

// pruneBackends wants RemovedBackends after the table it edits.
func TestPruneBackendsNeedsRemovedBackends(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "backend", "init", "init.go"))
	if err != nil {
		t.Fatal(err)
	}
	gone := regexp.MustCompile(`RemovedBackends = map\[string\]string\{`).ReplaceAll(src, []byte("Other = map[string]string{"))
	if _, err := pruneBackends(gone); err == nil || !strings.Contains(err.Error(), "RemovedBackends not found") {
		t.Errorf("got %v", err)
	}
	// Generate prunes the copy of init.go it finds in the tree.
	root, out := t.TempDir(), t.TempDir()
	writeTree(t, root, map[string]string{backendInit: string(src), "cmd/main.go": "package main\n"})
	if _, err := Generate(root, out); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(backendInit))); err != nil || !strings.Contains(string(b), "is not included in Conn3x") {
		t.Errorf("pruned copy: %v", err)
	}
}
