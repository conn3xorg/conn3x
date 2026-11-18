// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
)

// With backup = true, an edit that changes a file first copies it beside
// itself, with its mode; one that changes nothing, or a step without
// backup, makes no copy.
func TestEditStepBackup(t *testing.T) {
	ssh, dir := brShellHost(t)
	path := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(path, []byte("a=1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	copies := func() []string {
		got, _ := filepath.Glob(path + file.BackupSuffix + "*")
		return got
	}
	step := func(line string, backup bool) cty.Value {
		return eosStep("conn3x_line", map[string]cty.Value{"path": cty.StringVal(path), "line": cty.StringVal(line), "backup": cty.BoolVal(backup)}, ssh)
	}

	if _, err := unitCreate(t, "conn3x_line", step("b=2", false)); err != nil {
		t.Fatal(err)
	}
	if c := copies(); len(c) != 0 {
		t.Fatalf("an edit without backup made %v", c)
	}

	if _, err := unitCreate(t, "conn3x_line", step("c=3", true)); err != nil {
		t.Fatal(err)
	}
	c := copies()
	if len(c) != 1 {
		t.Fatalf("copies %v, want one", c)
	}
	if !strings.HasSuffix(c[0], "~") {
		t.Errorf("copy %s doesn't end in ~, so a .d directory would load it", c[0])
	}
	b, _ := os.ReadFile(c[0])
	if string(b) != "a=1\nb=2\n" {
		t.Errorf("the copy holds %q, want the file before the edit", b)
	}
	if fi, err := os.Stat(c[0]); err != nil || fi.Mode().Perm() != 0o640 {
		t.Errorf("the copy's mode: %v, %v", fi, err)
	}
	if b, _ := os.ReadFile(path); string(b) != "a=1\nb=2\nc=3\n" {
		t.Errorf("the file is %q", b)
	}

	// The line is there now, so applying again changes nothing and copies nothing.
	if _, err := unitCreate(t, "conn3x_line", step("c=3", true)); err != nil {
		t.Fatal(err)
	}
	if c := copies(); len(c) != 1 {
		t.Errorf("an edit that changed nothing made a copy: %v", c)
	}

	// Two backed-up edits back to back, as two line steps on one file run,
	// both land, with a copy each, even within one second.
	if _, err := unitCreate(t, "conn3x_line", step("d=4", true)); err != nil {
		t.Fatal(err)
	}
	if _, err := unitCreate(t, "conn3x_line", step("e=5", true)); err != nil {
		t.Fatalf("the second edit in a row: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "a=1\nb=2\nc=3\nd=4\ne=5\n" {
		t.Errorf("after two edits in a row the file is %q", b)
	}
	if c := copies(); len(c) != 3 {
		t.Errorf("copies %v, want three", c)
	}

	// A refused edit leaves the file and makes no copy.
	refused := brWith(step("f=6", true), map[string]cty.Value{"validate": cty.StringVal("false")})
	if _, err := unitCreate(t, "conn3x_line", refused); err == nil {
		t.Fatal("validate = false passed")
	}
	if c := copies(); len(c) != 3 {
		t.Errorf("a refused edit made a copy: %v", c)
	}
}
