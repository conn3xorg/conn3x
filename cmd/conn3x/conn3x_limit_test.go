// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/command/workdir"
)

func TestLimitReachesPlan(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	m := command.Meta{WorkingDir: workdir.NewDir(".")}
	if err := limitReachesPlan(m, nil); err != nil {
		t.Errorf("uninitialized: %v", err)
	}
	saved := "plan.tfplan"
	if err := limitReachesPlan(m, &saved); err == nil || !strings.Contains(err.Error(), "saved plan") {
		t.Errorf("saved plan: got %v, want it refused", err)
	}
	if err := os.MkdirAll(".terraform", 0o755); err != nil {
		t.Fatal(err)
	}
	for typ, refused := range map[string]bool{"s3": false, "remote": true, "cloud": true} {
		if err := os.WriteFile(filepath.Join(".terraform", "terraform.tfstate"), []byte(`{"version":3,"backend":{"type":"`+typ+`"}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := limitReachesPlan(m, nil); (err != nil) != refused {
			t.Errorf("%s backend: got %v, refused should be %v", typ, err, refused)
		}
	}
}
