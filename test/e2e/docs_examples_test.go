// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

var hclBlock = regexp.MustCompile("(?s)```hcl\n(.*?)```")

// Every example in the hand-written module pages must validate, so the docs
// never show a step that doesn't work.
func TestDocsExamplesValidate(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	pages, err := filepath.Glob(filepath.Join(filepath.Dir(here), "..", "..", "internal", "conn3x", "provider", "moddoc", "pages", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, page := range pages {
		data, err := os.ReadFile(page)
		if err != nil {
			t.Fatal(err)
		}
		for i, m := range hclBlock.FindAllStringSubmatch(string(data), -1) {
			name := strings.TrimSuffix(filepath.Base(page), ".md")
			t.Run(name+"/"+string(rune('a'+i)), func(t *testing.T) {
				dir := t.TempDir()
				src := "circuit \"docs\" {\n  hosts = { web1 = \"203.0.113.10\" }\n  ssh {\n    user = \"root\"\n  }\n\n" + m[1] + "\n}\n"
				if strings.HasPrefix(strings.TrimSpace(m[1]), "circuit ") {
					src = m[1]
				}
				if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(src), 0o644); err != nil {
					t.Fatal(err)
				}
				w := &workdir{t: t, dir: dir}
				w.mustConn3x("init", "-no-color")
				if out, code := w.conn3x("validate", "-no-color"); code != 0 {
					t.Fatalf("example %d in %s doesn't validate:\n%s\n%s", i+1, filepath.Base(page), src, out)
				}
			})
		}
	}
}
