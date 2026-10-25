// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/configs"
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
