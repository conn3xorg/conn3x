// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/configs"
	"github.com/opentofu/opentofu/internal/conn3x/provider"
)

func TestWritesAPagePerModule(t *testing.T) {
	dir := t.TempDir()
	if err := write(dir); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "sysctl.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"title: sysctl", "| `value` | string | Yes |", "| `in_sync` | bool |", "conn3x_sysctl"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("sysctl.md is missing %q:\n%s", want, got)
		}
	}
	pages, _ := filepath.Glob(filepath.Join(dir, "*.md"))
	if want := len(configs.Conn3xStepModules()); len(pages) != want {
		t.Errorf("%d pages for %d modules", len(pages), want)
	}
}

// When two arguments are alternatives ("Set this or ..."), the example sets
// one of them, so it's a valid step.
func TestExamplesSetOneOfAPair(t *testing.T) {
	p, err := provider.New()
	if err != nil {
		t.Fatal(err)
	}
	schemas := p.GetProviderSchema(context.Background()).ResourceTypes
	for name, want := range map[string]string{"file": "    content = \"...\"\n", "firewalld": "    port = \"...\"\n"} {
		rt := configs.Conn3xStepModules()[name]
		got := []byte(page(name, rt, schemas[rt].Block))
		example := strings.SplitN(strings.SplitN(string(got), "```hcl\n", 2)[1], "```", 2)[0]
		if !strings.Contains(example, want) {
			t.Errorf("%s example lacks %q:\n%s", name, want, example)
		}
		if name == "file" && strings.Contains(example, "content_wo") {
			t.Errorf("file example sets both of a pair:\n%s", example)
		}
	}
}

// A hand-written page goes around the generated reference: its part before
// the marker follows the description in place of the generated example, and
// its part after the marker closes the page.
func TestHandwrittenPageIsSpliced(t *testing.T) {
	gen := "---\ntitle: x\n---\n\nGen description.\n\n```hcl\ngenerated example\n```\n\n## Arguments\n\ntable\n\nA step lowers to x.\n"
	hand := "Intro.\n\n## Example usage\n\n```hcl\nhand example\n```\n<!-- reference -->\n## How it works\n\nNotes.\n"
	got := splice(gen, hand)
	for _, want := range []string{"Gen description.\n\nIntro.", "hand example", "## Arguments", "A step lowers to x.\n\n## How it works\n\nNotes."} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "generated example") || strings.Contains(got, "<!-- reference -->") {
		t.Errorf("generated example or marker left in:\n%s", got)
	}
	if splice(gen, "") != gen {
		t.Error("no hand-written page should leave the generated one as it is")
	}
}

// Every hand-written page belongs to a module that exists.
func TestHandwrittenPagesMatchModules(t *testing.T) {
	entries, err := pages.ReadDir("pages")
	if err != nil {
		t.Fatal(err)
	}
	mods := configs.Conn3xStepModules()
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".md")
		if _, ok := mods[name]; !ok && e.Name() != "README.md" {
			t.Errorf("pages/%s has no module", e.Name())
		}
	}
}

func TestMarksBothSidesOfAPair(t *testing.T) {
	dir := t.TempDir()
	if err := write(dir); err != nil {
		t.Fatal(err)
	}
	for page, names := range map[string][]string{
		"file":      {"content", "content_wo"},
		"firewalld": {"port", "service"},
		"wait_for":  {"path", "port"},
	} {
		got, err := os.ReadFile(filepath.Join(dir, page+".md"))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			if !strings.Contains(string(got), "| `"+name+"` |") ||
				!regexp.MustCompile("(?m)^\\| `"+name+"` \\| [^|]+ \\| One of \\|").Match(got) {
				t.Errorf("%s.md does not mark %s as One of:\n%s", page, name, got)
			}
		}
	}
	got, err := os.ReadFile(filepath.Join(dir, "sysctl.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile("(?m)^\\| `value` \\| string \\| Yes \\|").Match(got) {
		t.Error("a required single field no longer says Yes")
	}
	if !regexp.MustCompile("(?m)^\\| `on_remove` \\| string \\| No \\|").Match(got) {
		t.Error("an optional single field no longer says No")
	}
}
