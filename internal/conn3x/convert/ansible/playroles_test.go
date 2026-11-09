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

// convertPlay writes play beside a copy of the fixture's roles, adding
// extra roles as copies of web, and converts it with Options.Roles.
func convertPlay(t *testing.T, play string, extra ...string) Result {
	t.Helper()
	dir := t.TempDir()
	for _, name := range append([]string{"web"}, extra...) {
		if err := os.CopyFS(filepath.Join(dir, "roles", name), os.DirFS(filepath.Join("testdata", "playroles", "roles", "web"))); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "p.yml"), []byte(play), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := ConvertWith(filepath.Join(dir, "p.yml"), Options{Roles: true})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// Each of these would have run the role differently from Ansible, so the
// call is left for review instead of becoming a module.
func TestConvertPlayRolesRefusesWhatChangesTheRun(t *testing.T) {
	for play, want := range map[string]string{
		"- hosts: all\n  tasks:\n    - include_role:\n        name: web\n      with_items: [a, b]\n": "sets with_items on include_role",
		"- hosts: all\n  roles:\n    - role: web\n      become: \"{{ b }}\"\n":                       "sets become to something other than true or false",
		"- hosts: all\n  roles:\n    - role: web\n      tasks_from: other\n":                         "sets tasks_from on the role",
		"- hosts: all\n  no_log: true\n  roles:\n    - web\n":                                        "sets no_log",
		"- hosts: all\n  become: true\n  become_user: deploy\n  roles:\n    - web\n":                 "which its circuit wouldn't keep",
	} {
		res := convertPlay(t, play)
		if strings.Contains(string(res.HCL), "module ") || len(res.Review) == 0 || !strings.Contains(res.Review[len(res.Review)-1].Reason, want) {
			t.Errorf("%s: review %+v\n%s", play, res.Review, res.HCL)
		}
	}
}

// Roles whose names slug alike get their own directories, and a circuit
// split from one play doesn't take a later play's name.
func TestConvertPlayRolesNamesDontCollide(t *testing.T) {
	res := convertPlay(t, "- hosts: web\n  roles:\n    - web\n    - x.web\n    - web_2\n  tasks:\n    - name: After\n      package:\n        name: curl\n- name: web_2\n  hosts: other\n  tasks:\n    - name: Other\n      package:\n        name: tree\n", "x.web", "web_2")
	hcl := string(res.HCL)
	for _, dir := range []string{"circuit-web", "circuit-web_2", "circuit-web-2"} {
		if res.Files[dir+"/main.circuit.hcl"] == nil || !strings.Contains(hcl, `"./`+dir+`"`) {
			t.Errorf("no %s:\n%s", dir, hcl)
		}
	}
	if strings.Count(hcl, `circuit "web_2" {`) != 1 {
		t.Errorf("circuit names collide:\n%s", hcl)
	}
}

// A circuit after a role waits for it, and the role waits for the circuit
// before it, handlers included, as Ansible flushes them between sections.
// A handler that can't convert is listed for review once, though each
// circuit carries the play's handlers.
func TestConvertPlayRolesWaitsForHandlers(t *testing.T) {
	res := convertPlay(t, "- hosts: web\n  pre_tasks:\n    - name: Conf\n      copy:\n        content: x\n        dest: /etc/x\n      notify: Restart x\n  roles:\n    - web\n  tasks:\n    - name: After\n      package:\n        name: curl\n  handlers:\n    - name: Restart x\n      service:\n        name: x\n        state: restarted\n    - name: Odd\n      command: /bin/true\n")
	hcl := string(res.HCL)
	if !strings.Contains(hcl, "depends_on = [conn3x_file.web__conf, conn3x_service_action.web__restart_x]") || !strings.Contains(hcl, "depends_on = [module.web]") {
		t.Errorf("waits:\n%s", hcl)
	}
	odd := 0
	for _, r := range res.Review {
		if r.Task == "Odd" {
			odd++
		}
	}
	if odd != 1 {
		t.Errorf("the handler is listed %d times: %+v", odd, res.Review)
	}
}
