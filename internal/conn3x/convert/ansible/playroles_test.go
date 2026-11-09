// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The play's pre_tasks, its roles, its tasks and an include_role in them
// become circuits and modules that each wait for the one before, and the
// role converts once into a circuit directory both calls share.
func TestConvertPlayRoles(t *testing.T) {
	res, err := ConvertWith(filepath.Join("testdata", "playroles", "site.yml"), Options{Roles: true})
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "playroles", "site.tf")
	if *update {
		if err := os.WriteFile(golden, res.HCL, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(res.HCL) {
		t.Errorf("site.tf differs from %s (run with -update to accept):\n%s", golden, res.HCL)
	}
	for _, p := range []string{"main.circuit.hcl", "variables.tf", "outputs.tf", "README.md"} {
		if res.Files["circuit-web/"+p] == nil {
			t.Errorf("circuit-web/%s wasn't written", p)
		}
	}
	if len(res.Files) != 4 {
		t.Errorf("wrote %d files, want the role's 4 once", len(res.Files))
	}
	// curl, the motd and the include_role, then the role's two tasks.
	if res.Converted != 5 {
		t.Errorf("converted %d, want 5", res.Converted)
	}
	if len(res.Review) != 2 || !strings.Contains(res.Review[0].Reason, "passes web_extra") || !strings.Contains(res.Review[1].Reason, "isn't at roles/missing") {
		t.Errorf("review: %+v", res.Review)
	}
}

// Without Options.Roles there's nowhere to write a role's circuit, so the
// play's roles are left for review, saying how to convert them.
func TestConvertPlayRolesNeedOut(t *testing.T) {
	res, err := Convert(filepath.Join("testdata", "playroles", "site.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 0 || !strings.Contains(string(res.HCL), "convert with -out") || strings.Contains(string(res.HCL), "module ") {
		t.Errorf("files %d:\n%s", len(res.Files), res.HCL)
	}
}

// A role call that sets what the converter can't carry over, such as
// tasks_from or when, is left for review where it was.
func TestConvertPlayRolesRefuses(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(filepath.Join(dir, "roles"), os.DirFS(filepath.Join("testdata", "playroles", "roles"))); err != nil {
		t.Fatal(err)
	}
	play := "- hosts: all\n  roles:\n    - role: web\n      when: x\n  tasks:\n    - include_role:\n        name: web\n        tasks_from: other\n"
	if err := os.WriteFile(filepath.Join(dir, "p.yml"), []byte(play), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := ConvertWith(filepath.Join(dir, "p.yml"), Options{Roles: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Review) != 2 || !strings.Contains(res.Review[0].Reason, "sets when on the role") || !strings.Contains(res.Review[1].Reason, "sets tasks_from on include_role") {
		t.Errorf("review: %+v", res.Review)
	}
	if strings.Contains(string(res.HCL), "module ") {
		t.Errorf("wrote a module:\n%s", res.HCL)
	}
}
