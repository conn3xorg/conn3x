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

// views.HelpPrompt fills in the subcommand with %s.
func TestRewriteHelpPrompt(t *testing.T) {
	got := rewriteLiteral("`\nFor more help on using this command, run:\n  tofu %s -help\n`")
	if !strings.Contains(got, "  conn3x %s -help") {
		t.Fatalf("got %q", got)
	}
}

// Upstream diagnostics about pre-fork behavior name the version that had
// it, "OpenTofu 0.11", which the blanket OpenTofu->Conn3x replace would
// otherwise turn into an equally wrong "Conn3x 0.11": OpenTofu forked from
// Terraform at 1.6 and never had a 0.x release.
func TestRewriteKeepsPreForkVersionAsTerraform(t *testing.T) {
	got := rewriteLiteral("OpenTofu 0.11 and earlier required quotes, but quoted references are now deprecated and will be removed in a future version of OpenTofu.")
	want := "Terraform 0.11 and earlier required quotes, but quoted references are now deprecated and will be removed in a future version of Conn3x."
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

// The version message at the top of every -json stream names the Conn3x
// release, not OpenTofu's version under the Conn3x name.
func TestGenerateBrandsJSONVersion(t *testing.T) {
	src, err := os.ReadFile("../../command/views/json_view.go")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	p := filepath.Join(root, "internal/command/views/json_view.go")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "cmd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, src, 0o644); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if _, err := Generate(root, out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(out, "internal/command/views/json_view.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"conn3xversion.String()", `"conn3x", conn3xversion.Version`, `conn3xversion "github.com/opentofu/opentofu/internal/conn3x/version"`} {
		if !strings.Contains(string(got), want) {
			t.Errorf("rewritten json_view.go lacks %s", want)
		}
	}
}

// generateFrom copies files of the real tree, by their path from its root,
// into an empty one, generates its overlay and returns what the overlay has
// for each: the rewritten copy, or the source when it needed no rewrite.
func generateFrom(t *testing.T, files ...string) map[string]string {
	t.Helper()
	root, out := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "cmd"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		src, err := os.ReadFile(filepath.Join("../../..", f))
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(root, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, src, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Generate(root, out); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(out, f))
		if os.IsNotExist(err) {
			b, err = os.ReadFile(filepath.Join(root, f))
		}
		if err != nil {
			t.Fatal(err)
		}
		got[f] = string(b)
	}
	return got
}

// The magic strings of the external key provider and encryption method
// protocols stay OpenTofu's, so a program written for OpenTofu still works.
func TestGenerateKeepsEncryptionProtocolMagic(t *testing.T) {
	got := generateFrom(t,
		"internal/encryption/keyprovider/external/protocol.go",
		"internal/encryption/method/external/protocol.go",
		"internal/encryption/keyprovider/external/provider.go",
		"internal/encryption/method/external/command.go",
	)
	for f, want := range map[string]string{
		"internal/encryption/keyprovider/external/protocol.go": `const HeaderMagic = "OpenTofu-External-Key-Provider"`,
		"internal/encryption/method/external/protocol.go":      `const Magic = "OpenTofu-External-Encryption-Method"`,
	} {
		if !strings.Contains(got[f], want) {
			t.Errorf("%s no longer has %s", f, want)
		}
	}
	for f, src := range got {
		if strings.Contains(src, "Conn3x-External-") {
			t.Errorf("%s renames the protocol's magic string", f)
		}
	}
	if got := rewriteLiteral(`"OpenTofu expects the header OpenTofu-External-Key-Provider"`); got != `"Conn3x expects the header OpenTofu-External-Key-Provider"` {
		t.Errorf("rewriteLiteral = %s", got)
	}
}

// The plan renderer's multi-line strings and the text of errors and
// warnings go through termsafe.Escape. An upstream change that moves the
// patched lines fails here, not in a release.
func TestGenerateEscapesHostText(t *testing.T) {
	got := generateFrom(t,
		"internal/command/jsonformat/computed/renderers/string.go",
		"internal/command/jsonformat/computed/renderers/primitive.go",
		"internal/command/format/diagnostic.go",
	)
	for f, wants := range map[string][]string{
		"internal/command/format/diagnostic.go":                       {"func conn3xSafe(", "termsafe.Escape(diag.Description().Summary)", `"github.com/opentofu/opentofu/internal/conn3x/termsafe"`},
		"internal/command/jsonformat/computed/renderers/string.go":    {"termsafe.Escape(strings.TrimSpace(str))", "func (e evaluatedString) conn3xLines() []string", `"github.com/opentofu/opentofu/internal/conn3x/termsafe"`},
		"internal/command/jsonformat/computed/renderers/primitive.go": {"beforeLines := beforeString.conn3xLines()", "afterLines := afterString.conn3xLines()"},
	} {
		for _, want := range wants {
			if !strings.Contains(got[f], want) {
				t.Errorf("rewritten %s lacks %s", f, want)
			}
		}
	}
}
