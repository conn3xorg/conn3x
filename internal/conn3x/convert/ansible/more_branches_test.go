// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertTLSMore(t *testing.T) {
	for task, wants := range map[string][]string{
		"community.crypto.openssl_privatekey: {path: /k, size: 2048}":                                                              {"bits = 2048"},
		"community.crypto.openssl_csr: {path: /c, privatekey_path: /k, common_name: w, subject_alt_name: ['IP:10.0.0.1']}":         {`ip_addresses = ["10.0.0.1"]`},
		"community.crypto.openssl_csr: {path: /c, privatekey_path: /k, common_name: w, use_common_name_for_san: no, mode: '0644'}": {`mode        = "0644"`},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		hcl := string(res.HCL)
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
			continue
		}
		for _, want := range wants {
			if !strings.Contains(hcl, want) {
				t.Errorf("%s: output lacks %q:\n%s", task, want, hcl)
			}
		}
		if strings.Contains(task, "IP:") || strings.Contains(task, "use_common_name_for_san") {
			if strings.Contains(hcl, "dns_names") {
				t.Errorf("%s: asked for DNS names:\n%s", task, hcl)
			}
		}
	}
	for task, reason := range map[string]string{
		"community.crypto.openssl_privatekey: {path: /k, size: big}":                   "sets size big",
		"community.crypto.openssl_privatekey: {path: /k, type: ECC, curve: secp521r1}": "uses an ECC curve other than secp256r1 or secp384r1",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, reason)
		}
	}
}

// debug's note says what it printed, without copying it.
func TestDebugNotes(t *testing.T) {
	for task, want := range map[string]string{
		"debug: 'msg={{ x }}'":     "It printed a templated message",
		"debug: 'msg=hello'":       "Its message isn't copied here",
		"debug: { var: x }":        "It printed the variable x",
		"debug: { var: 'x.y[0]' }": "It printed an expression",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		notes := ""
		for _, n := range res.Notes {
			notes += n.Reason
		}
		if len(res.Review) != 0 || !strings.Contains(string(res.HCL)+notes, want) {
			t.Errorf("%s: review %+v, notes %q:\n%s", task, res.Review, notes, res.HCL)
		}
	}
}

// Each way PyYAML writes true or false makes a role default a bool.
func TestRoleBoolDefaultSpellings(t *testing.T) {
	for _, c := range []struct{ word, want string }{
		{"Yes", "true"}, {"YES", "true"}, {"True", "true"}, {"TRUE", "true"}, {"on", "true"}, {"On", "true"}, {"ON", "true"},
		{"no", "false"}, {"NO", "false"}, {"False", "false"}, {"FALSE", "false"}, {"off", "false"}, {"Off", "false"}, {"OFF", "false"},
	} {
		res, err := ConvertRole(writeRole(t, map[string]string{
			"defaults/main.yml": "flag: " + c.word + "\n",
			"tasks/main.yml":    "- name: Web\n  package: { name: nginx }\n  when: flag | bool\n",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if vars := string(res.Files["variables.tf"]); !strings.Contains(vars, "type        = bool\n  default     = "+c.want) || res.Converted != 1 {
			t.Errorf("flag: %s: converted %d, review %+v\n%s", c.word, res.Converted, res.Review, vars)
		}
	}
}

// A role call's become converts when it's a plain true or false, written
// any way Ansible reads it.
func TestConvertPlayRolesBecomeWords(t *testing.T) {
	for _, word := range []string{"true", "yes", "on", "false", "no", "off"} {
		for _, play := range []string{
			"- hosts: all\n  roles:\n    - role: web\n      become: '" + word + "'\n",
			"- hosts: all\n  tasks:\n    - include_role:\n        name: web\n      become: '" + word + "'\n",
		} {
			res := convertPlay(t, play)
			if !strings.Contains(string(res.HCL), "module \"web\"") || len(res.Review) != 0 {
				t.Errorf("%s: review %+v\n%s", play, res.Review, res.HCL)
			}
		}
	}
}

func TestConvertPlayRolesRefusesMore(t *testing.T) {
	for play, want := range map[string]string{
		"- hosts: all\n  roles:\n    - role: web\n      tags: [never]\n":                                    neverReason,
		"- hosts: all\n  tags: never\n  roles:\n    - web\n":                                                neverReason,
		"- hosts: all\n  roles:\n    - role: ''\n":                                                          "runs a role without naming it",
		"- hosts: all\n  roles:\n    - '{{ r }}'\n":                                                         "names its role with a Jinja expression",
		"- hosts: all\n  tasks:\n    - include_role:\n        name: web\n      tags: [never]\n":             neverReason,
		"- hosts: all\n  tasks:\n    - include_role:\n        name: web\n        tasks_from: ''\n":          "sets tasks_from to something other than a file name",
		"- hosts: all\n  tasks:\n    - include_role:\n        name: web\n        apply: { become: true }\n": "sets apply on include_role",
		"- hosts: all\n  tasks:\n    - include_role:\n        name: web\n      when: x\n":                   "sets when on include_role",
		"- hosts: all\n  tasks:\n    - include_role:\n        name: web\n      register: r\n":               "sets register on include_role",
	} {
		res := convertPlay(t, play)
		if strings.Contains(string(res.HCL), "module ") || len(res.Review) == 0 || !strings.Contains(reasons(res), want) {
			t.Errorf("%s: review %+v\n%s", play, res.Review, res.HCL)
		}
	}
	// A role named by its path, beside the playbook, is found there.
	res := convertPlay(t, "- hosts: all\n  roles:\n    - roles/web\n")
	if !strings.Contains(string(res.HCL), "module ") || len(res.Review) != 0 {
		t.Errorf("by path: review %+v\n%s", res.Review, res.HCL)
	}
}

// A probe the converter can't carry to a data source stays, saying why.
func TestRoleProbeRefusalsMore(t *testing.T) {
	for extra, want := range map[string]string{
		"  register: php\n  with_items: [a]":      "sets with_items on a probe",
		"  register: php\n  failed_when: maybe":   "uses a failed_when other than false",
		"  register: php\n  failed_when: true":    "uses a failed_when other than false",
		"  register: php\n  ignore_errors: false": "sets ignore_errors to something other than true",
		"  register: '{{ r }}'":                   `registers "{{ r }}"`,
		"  register: php\n  args: { stdin: x }":   "sets args on a probe",
	} {
		res, err := ConvertRole(writeRole(t, map[string]string{
			"tasks/main.yml": "- name: Which php\n  command: which php\n  changed_when: false\n" + extra + "\n",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, want) {
			t.Errorf("%s: review %+v, want %q", extra, res.Review, want)
		}
	}
	res, err := ConvertRole(writeRole(t, map[string]string{
		"tasks/main.yml": "- name: Which php\n  command: { cmd: which php, stdin: x }\n  changed_when: false\n  register: php\n",
	}))
	if err != nil || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "sets stdin, which the converter can't translate yet") {
		t.Errorf("unused argument: %v, review %+v", err, res.Review)
	}
}

// A role task's when built with and, or, not and parentheses becomes the
// same expression; a part the converter can't read leaves it for review.
func TestRoleWhenCombined(t *testing.T) {
	for when, want := range map[string]string{
		"(a | bool) and not (b | bool)":             "when = (var.a) && (!(var.b))",
		"a | bool or ansible_os_family == 'Debian'": `when = (var.a) || (local.os_family[each.key] == "debian")`,
		"((a | bool))":                               "when = var.a",
		"(a | bool) or (b | bool) and a | bool":      "when = (var.a) || ((var.b) && (var.a))",
		"a | bool and ansible_os_family != 'RedHat'": `local.os_family[each.key] != "redhat"`,
	} {
		res, err := ConvertRole(writeRole(t, map[string]string{
			"defaults/main.yml": "a: true\nb: false\n",
			"tasks/main.yml":    "- name: Web\n  package: { name: nginx }\n  when: \"" + when + "\"\n",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if hcl := string(res.Files["main.circuit.hcl"]); res.Converted != 1 || !strings.Contains(hcl, want) {
			t.Errorf("%s: converted %d, review %+v\n%s", when, res.Converted, res.Review, hcl)
		}
	}
	for _, when := range []string{"(a | bool) and c", "not c", "a | bool or ansible_os_family == 'Plan9'", "(a | bool) and (b"} {
		res, err := ConvertRole(writeRole(t, map[string]string{
			"defaults/main.yml": "a: true\nb: false\n",
			"tasks/main.yml":    "- name: Web\n  package: { name: nginx }\n  when: \"" + when + "\"\n",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "uses when") {
			t.Errorf("%s: converted %d, review %+v", when, res.Converted, res.Review)
		}
	}
}

// Which set_fact tasks are the caller-or-family pattern, and what a task
// using such a variable can do with it.
func TestRoleFamilyDefaultsMore(t *testing.T) {
	include := "- name: Vars\n  include_vars: \"{{ ansible_os_family }}.yml\"\n"
	vars := map[string]string{"vars/Debian.yml": "__u: www-data\n__g: www\n", "vars/RedHat.yml": "__u: nginx\n__g: nginx\n"}
	role := func(tasks string) Result {
		t.Helper()
		files := map[string]string{"tasks/main.yml": include + tasks}
		for k, v := range vars {
			files[k] = v
		}
		res, err := ConvertRole(writeRole(t, files))
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	// A when written as a one-item list is the same pattern.
	res := role("- set_fact: {u: '{{ __u }}'}\n  when: [u is not defined]\n- name: D\n  file: {path: /srv, state: directory, owner: '{{ u }}'}\n")
	if hcl := string(res.Files["main.circuit.hcl"]); len(res.Review) != 0 || !strings.Contains(hcl, `owner = var.u != null ? var.u : { debian = "www-data", redhat = "nginx" }[local.os_family[each.key]]`) {
		t.Errorf("one-item when: review %+v\n%s", res.Review, hcl)
	}

	// Anything else stays a set_fact, whose when goes to review.
	for name, tasks := range map[string]string{
		"two facts":       "- set_fact: {u: '{{ __u }}', g: '{{ __g }}'}\n  when: u is not defined\n",
		"not a bare ref":  "- set_fact: {u: '{{ __u | upper }}'}\n  when: u is not defined\n",
		"another when":    "- set_fact: {u: '{{ __u }}'}\n  when: u is defined\n",
		"one family only": "- set_fact: {u: '{{ __x }}'}\n  when: u is not defined\n",
		"a list value":    "- set_fact: {u: ['{{ __u }}']}\n  when: u is not defined\n",
	} {
		res := role(tasks)
		if len(res.Review) != 1 || res.Review[0].Line != 3 || res.Review[0].Reason != "uses when, which the converter can't translate yet" {
			t.Errorf("%s: review %+v", name, res.Review)
		}
	}

	both := "- set_fact: {u: '{{ __u }}'}\n  when: u is not defined\n- set_fact: {g: '{{ __g }}'}\n  when: g is not defined\n"
	if res := role(both + "- name: C\n  copy: {dest: /etc/a, content: '{{ u }}:{{ g }}'}\n"); !strings.Contains(reasons(res), "content combines several values the caller can set") {
		t.Errorf("two caller values: review %+v", res.Review)
	}
}

// The forms of a per-family include_vars and include_tasks.
func TestRoleFamilyIncludesMore(t *testing.T) {
	use := "- name: P\n  package: {name: '{{ pkg }}'}\n"
	fam := map[string]string{"vars/Debian.yml": "pkg: cron\n", "vars/RedHat.yml": "pkg: cronie\n"}
	role := func(files map[string]string) Result {
		t.Helper()
		for k, v := range fam {
			if _, ok := files[k]; !ok {
				files[k] = v
			}
		}
		res, err := ConvertRole(writeRole(t, files))
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	res := role(map[string]string{"tasks/main.yml": "- include_vars: { file: '{{ ansible_os_family }}.yml' }\n" + use})
	if hcl := string(res.Files["main.circuit.hcl"]); len(res.Review) != 0 || !strings.Contains(hcl, `{ debian = "cron", redhat = "cronie" }`) {
		t.Errorf("include_vars with file: review %+v\n%s", res.Review, hcl)
	}
	// with_first_found reads item; any other name isn't the pattern.
	res = role(map[string]string{"tasks/main.yml": "- include_vars: '{{ f }}'\n  with_first_found: ['{{ ansible_os_family }}.yml']\n" + use})
	if !strings.Contains(reasons(res), "include_vars") {
		t.Errorf("first_found without item: review %+v", res.Review)
	}

	for name, c := range map[string]struct {
		files map[string]string
		want  string
	}{
		"no family meets": {map[string]string{"tasks/main.yml": "- include_tasks: arch.yml\n  when: ansible_os_family == 'Archlinux'\n"},
			"includes arch.yml with a when no Debian or Red Hat family host meets"},
		"missing file": {map[string]string{"tasks/main.yml": "- include_tasks: gone.yml\n  when: ansible_os_family == 'Debian'\n"},
			"imports gone.yml, which wasn't found"},
		"one family missing": {map[string]string{"tasks/main.yml": "- include_tasks: 'setup-{{ ansible_os_family }}.yml'\n", "tasks/setup-Debian.yml": "- package: {name: a}\n"},
			"includes a file per family, and for RedHat hosts it imports setup-RedHat.yml, which wasn't found"},
		"a loop": {map[string]string{"tasks/main.yml": "- include_tasks: 'setup-{{ ansible_os_family }}.yml'\n  loop: [a]\n"},
			"uses include_tasks"},
	} {
		if got := reasons(role(c.files)); !strings.Contains(got, c.want) {
			t.Errorf("%s: review %q, want %q", name, got, c.want)
		}
	}

	// A family include's when lands on each task it inlines; one it can't
	// inline keeps its own reason.
	res = role(map[string]string{
		"tasks/main.yml": "- include_tasks: deb.yml\n  when: [ansible_os_family == 'Debian']\n",
		"tasks/deb.yml":  "- package: {name: a}\n- command: 'true'\n",
	})
	if hcl := string(res.Files["main.circuit.hcl"]); res.Converted != 1 || !strings.Contains(hcl, `when = local.os_family[each.key] == "debian"`) || !strings.Contains(reasons(res), "runs on every play") {
		t.Errorf("converted %d, review %+v\n%s", res.Converted, res.Review, hcl)
	}
}
