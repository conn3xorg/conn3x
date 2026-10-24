// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package brand

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRewriteSource(t *testing.T) {
	src := "package x\n\n" +
		"// OpenTofu comments stay as they are.\n" +
		"var OpenTofuName = \"OpenTofu will perform the following actions:\"\n" +
		"var hint = `Run \"tofu init\" first, then tofu plan.`\n" +
		"var ext = \".tofu\"\n" +
		"var env = \"TOFU_LOG\"\n" +
		"var rc = \"tofu.rc\"\n" +
		"var url = \"https://opentofu.org/docs\"\n" +
		"var help = \"Usage: tofu [global options] plan\"\n" +
		"var bare = \"tofu\"\n"
	got, changed, err := rewriteSource([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("nothing rewritten")
	}
	want := "package x\n\n" +
		"// OpenTofu comments stay as they are.\n" +
		"var OpenTofuName = \"Conn3x will perform the following actions:\"\n" +
		"var hint = `Run \"conn3x init\" first, then conn3x plan.`\n" +
		"var ext = \".tofu\"\n" +
		"var env = \"TOFU_LOG\"\n" +
		"var rc = \"tofu.rc\"\n" +
		"var url = \"https://opentofu.org/docs\"\n" +
		"var help = \"Usage: conn3x [global options] plan\"\n" +
		"var bare = \"tofu\"\n"
	if string(got) != want {
		t.Fatalf("rewrite mismatch:\n%s\nwant:\n%s", got, want)
	}
}

func TestRewriteLeavesUnrelatedFilesAlone(t *testing.T) {
	_, changed, err := rewriteSource([]byte("package x\n\nvar s = \"hello\"\n"))
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
}

func TestGenerateOverlay(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("internal/command/a.go", "package command\n\nvar s = \"OpenTofu\"\n")
	write("internal/command/a_test.go", "package command\n\nvar t = \"OpenTofu\"\n")
	write("internal/command/b.go", "package command\n\nvar s2 = \"plain\"\n")
	write("internal/conn3x/c.go", "package conn3x\n\nvar s = \"built on OpenTofu\"\n")
	write("cmd/conn3x/version.go", "package main\n\nvar s = \"built on OpenTofu\"\n")
	write("cmd/tofu/main.go", "package main\n\nvar s = \"OpenTofu\"\n")

	out := t.TempDir()
	overlay, err := Generate(root, out)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(overlay)
	if err != nil {
		t.Fatal(err)
	}
	var o struct{ Replace map[string]string }
	if err := json.Unmarshal(data, &o); err != nil {
		t.Fatal(err)
	}
	if len(o.Replace) != 1 {
		t.Fatalf("overlay replaces %d files, want only internal/command/a.go: %v", len(o.Replace), o.Replace)
	}
	for orig, repl := range o.Replace {
		if !strings.HasSuffix(orig, filepath.Join("internal", "command", "a.go")) {
			t.Fatalf("unexpected file in overlay: %s", orig)
		}
		got, _ := os.ReadFile(repl)
		if !strings.Contains(string(got), "\"Conn3x\"") {
			t.Fatalf("replacement not rewritten: %s", got)
		}
	}
}
