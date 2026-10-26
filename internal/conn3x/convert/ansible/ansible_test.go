// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2/hclparse"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func TestConvertGolden(t *testing.T) {
	res, err := Convert(filepath.Join("testdata", "web", "site.yml"))
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "web", "site.tf")
	if *update {
		if err := os.WriteFile(golden, res.HCL, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.HCL) != string(want) {
		t.Fatalf("output differs from %s (run with -update to accept):\n%s", golden, res.HCL)
	}
	if _, diags := hclparse.NewParser().ParseHCL(res.HCL, "site.tf"); diags.HasErrors() {
		t.Fatalf("output is not valid HCL: %s", diags)
	}
	if res.Converted != 10 || len(res.Review) != 1 {
		t.Fatalf("converted %d, review %v", res.Converted, res.Review)
	}
	for _, want := range []string{"debug"} {
		found := false
		for _, r := range res.Review {
			found = found || strings.Contains(r.Reason, want)
		}
		if !found {
			t.Errorf("no review item mentions %q: %v", want, res.Review)
		}
	}
}

func convertString(t *testing.T, playbook string) Result {
	t.Helper()
	path := filepath.Join(t.TempDir(), "play.yml")
	if err := os.WriteFile(path, []byte(playbook), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Convert(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, diags := hclparse.NewParser().ParseHCL(res.HCL, "play.tf"); diags.HasErrors() {
		t.Fatalf("output is not valid HCL: %s\n%s", diags, res.HCL)
	}
	return res
}

// Each of these must be left for a person, never half-translated.
func TestRefusesWhatItCantProve(t *testing.T) {
	for reason, task := range map[string]string{
		"runs on every play":      "command: /usr/local/bin/migrate",
		"no sha256 checksum":      "get_url: {url: 'https://example.com/a', dest: /opt/a}",
		"sets backup_dir":         "copy: {dest: /etc/a, content: x, backup_dir: /tmp}",
		`refers to "port"`:        "lineinfile: {path: /etc/a, line: 'listen {{ port }}'}",
		"Jinja expression":        "copy: {dest: /etc/a, content: \"{{ name | upper }}\"}",
		"uses when":               "package: {name: vim}\n      when: ansible_os_family == 'Debian'",
		"uses register":           "command: {cmd: id, creates: /x}\n      register: out",
		"Jinja template":          "template: {src: a.j2, dest: /etc/a}",
		"appends to the user's":   "user: {name: bob, groups: wheel, append: true}",
		"permanent and immediate": "firewalld: {service: http, permanent: true, state: enabled}",
		"mode on a link":          "file: {src: /opt/a, dest: /usr/local/bin/a, state: link, owner: root}",
	} {
		res := convertString(t, "- hosts: all\n  vars: {name: x}\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%q: converted %d, review %+v", task, res.Converted, res.Review)
		}
		if !strings.Contains(string(res.HCL), "TODO(convert)") {
			t.Errorf("%q: no TODO in the output", task)
		}
	}
}

func TestHandlerThatIsNotAServiceIsLeft(t *testing.T) {
	res := convertString(t, `- hosts: all
  tasks:
    - copy: {dest: /etc/a, content: x}
      notify: rebuild
  handlers:
    - name: rebuild
      command: make
`)
	if res.Converted != 0 || len(res.Review) != 2 {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
}

func TestConvertsLiteralLoops(t *testing.T) {
	res := convertString(t, `- hosts: all
  tasks:
    - name: Tools
      package:
        name: "{{ item }}"
      loop: [git, jq]
    - name: Config files
      copy:
        dest: "/etc/app/{{ item }}.conf"
        content: "managed\n"
      loop:
        - api
        - worker
`)
	if res.Converted != 2 || len(res.Review) != 0 {
		t.Fatalf("converted %d, review %+v\n%s", res.Converted, res.Review, res.HCL)
	}
	for _, want := range []string{
		`for_each = ["git", "jq"]`,
		`name = item.value`,
		`for_each = ["api", "worker"]`,
		`path    = "/etc/app/${item.value}.conf"`,
	} {
		if !strings.Contains(string(res.HCL), want) {
			t.Errorf("output lacks %q:\n%s", want, res.HCL)
		}
	}
}

// Loops the converter can't prove the same stay for a person.
func TestRefusesOtherLoops(t *testing.T) {
	for reason, task := range map[string]string{
		"loop over a variable": "package: {name: \"{{ item }}\"}\n      loop: \"{{ pkgs }}\"",
		"item.name":            "user: {name: \"{{ item.name }}\"}\n      loop: [{name: a}, {name: b}]",
		"uses when":            "package: {name: \"{{ item }}\"}\n      loop: [a, b]\n      when: x",
		"doesn't use item":     "package: {name: vim}\n      loop: [a, b]",
		"uses loop_control":    "package: {name: \"{{ i }}\"}\n      loop: [a, b]\n      loop_control: {loop_var: i}",
	} {
		res := convertString(t, "- hosts: all\n  vars: {pkgs: x}\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%q: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}
