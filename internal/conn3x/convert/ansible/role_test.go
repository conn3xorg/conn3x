// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2/hclparse"
	"gopkg.in/yaml.v3"
)

// goldenRole converts testdata/role/<name> and compares every file with
// testdata/role/<name>.circuit.
func goldenRole(t *testing.T, name string) Result {
	t.Helper()
	res, err := ConvertRole(filepath.Join("testdata", "role", name))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("testdata", "role", name+".circuit")
	if *update {
		os.RemoveAll(dir)
		for p, b := range res.Files {
			if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, p), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	want := map[string]bool{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			want[filepath.ToSlash(rel)] = true
		}
		return err
	})
	for p, b := range res.Files {
		golden, err := os.ReadFile(filepath.Join(dir, p))
		if err != nil {
			t.Errorf("%s is new (run with -update to accept):\n%s", p, b)
			continue
		}
		delete(want, p)
		if string(golden) != string(b) {
			t.Errorf("%s differs from %s (run with -update to accept):\n%s", p, dir, b)
		}
		if strings.HasSuffix(p, ".hcl") || strings.HasSuffix(p, ".tf") {
			if _, diags := hclparse.NewParser().ParseHCL(b, p); diags.HasErrors() {
				t.Errorf("%s is not valid HCL: %s", p, diags)
			}
		}
	}
	for p := range want {
		t.Errorf("%s is no longer written", p)
	}
	return res
}

func TestConvertRoleGolden(t *testing.T) {
	res := goldenRole(t, "app")
	if res.Converted != 7 || len(res.Review) != 0 {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
}

func TestConvertRoleRefuses(t *testing.T) {
	res := goldenRole(t, "mixed")
	for _, want := range []string{
		"runs the roles common, geerlingguy.firewall first",
		"checks the role's arguments",
		"uses include_tasks, which Ansible reads only when the play reaches it",
		"sets when on import_tasks",
		"imports nowhere.yml, which wasn't found",
		"which is already being imported",
		"uses include_role",
		"sets become, which in a circuit the ssh block decides",
		`mode refers to the role default "mixed_mode"`,
		`path refers to the role default "mixed_conf_dir"`,
		"uses Jinja statements",
		"is outside the role's files/",
	} {
		found := false
		for _, r := range res.Review {
			found = found || strings.Contains(r.Reason, want)
		}
		if !found {
			t.Errorf("no review item says %q: %+v", want, res.Review)
		}
	}
	if res.Converted != 0 || len(res.Review) != 12 {
		t.Errorf("converted %d, review %d", res.Converted, len(res.Review))
	}
}

func TestRolePlainValues(t *testing.T) {
	src := `
s: hello
q: "yes"
p: /opt/app
i: 8080
neg: -1
oct: 0777
f: 1.5
b: yes
B: True
null1: ~
empty:
date: 2026-11-07
list: [a]
txt: "[a, b]"
jinja: "{{ x }}"
lit: |
  two
  lines
`
	want := map[string]string{"s": "hello", "q": "yes", "p": "/opt/app", "i": "8080#", "neg": "-1#", "lit": "two\nlines\n"}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	for _, kv := range pairs(doc.Content[0]) {
		v, num, why := plainValue(kv[1])
		got := v
		if num {
			got += "#"
		}
		if why != "" {
			got = ""
		}
		if got != want[kv[0].Value] {
			t.Errorf("%s: got %q (%s), want %q", kv[0].Value, got, why, want[kv[0].Value])
		}
	}
}

func TestConvertRoleNeedsTasks(t *testing.T) {
	if _, err := ConvertRole(t.TempDir()); err == nil || !strings.Contains(err.Error(), "no tasks/ directory") {
		t.Fatalf("got %v", err)
	}
}

// A playbook's import_tasks inlines too, from beside the playbook.
func TestPlaybookImportTasks(t *testing.T) {
	dir := t.TempDir()
	for name, src := range map[string]string{
		"more.yml": "- name: Tools\n  package: {name: jq}\n",
		"play.yml": "- hosts: all\n  tasks:\n    - import_tasks: more.yml\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Convert(filepath.Join(dir, "play.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Converted != 1 || len(res.Review) != 0 || !strings.Contains(string(res.HCL), `name = "jq"`) {
		t.Fatalf("converted %d, review %+v\n%s", res.Converted, res.Review, res.HCL)
	}
}

// A variable set per OS under vars/ says where it comes from, until the
// converter can translate the include_vars that loads it.
func TestRoleVariableFromAnIncludeVarsFile(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"vars/Debian.yml": "nginx_user: www-data\n",
		"vars/RedHat.yml": "nginx_user: nginx\n",
		"vars/main.yml":   "unrelated: x\n",
		"tasks/main.yml":  "- name: Owner\n  file: {path: /srv/www, state: directory, owner: '{{ nginx_user }}'}\n- name: Other\n  file: {path: /srv/x, state: directory, owner: '{{ nope }}'}\n",
	})
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Review) != 2 {
		t.Fatalf("review %+v", res.Review)
	}
	want := `refers to "nginx_user", which is set in vars/Debian.yml and vars/RedHat.yml, loaded by an include_vars`
	if !strings.Contains(res.Review[0].Reason, want) {
		t.Errorf("reason = %q, want it to contain %q", res.Review[0].Reason, want)
	}
	if !strings.Contains(res.Review[1].Reason, `which isn't a role variable the converter can fill in`) {
		t.Errorf("a variable from nowhere kept the old reason: %q", res.Review[1].Reason)
	}
}

// A handler's service name fills in play vars, and anything but a service
// restart or reload, or a when, stays for review.
func TestHandlerNameFromAVarAndKeywords(t *testing.T) {
	res := convertString(t, `- hosts: all
  vars: {svc: nginx}
  tasks:
    - copy: {dest: /etc/a, content: x}
      notify: [Restart, Maybe]
  handlers:
    - name: Restart
      service: {name: "{{ svc }}", state: restarted}
    - name: Maybe
      service: {name: nginx, state: reloaded}
      when: false
`)
	if !strings.Contains(string(res.HCL), `name   = "nginx"`) || len(res.Review) != 2 || !strings.Contains(res.Review[0].Reason, "uses when") {
		t.Fatalf("review %+v\n%s", res.Review, res.HCL)
	}
}

// writeRole writes a role's files into a new directory.
func writeRole(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}
