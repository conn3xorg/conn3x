// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// A loop over maps written in the task becomes for_each over them, keyed
// by a field every item has, with a missing field at its default. Each
// item is checked by itself, as a written list of plain values is.
func TestLiteralMapLoop(t *testing.T) {
	res := convertString(t, `- hosts: all
  become: true
  tasks:
    - name: Users
      user: {name: "{{ item.name }}", shell: "{{ item.shell | default('/bin/sh') }}"}
      loop:
        - {name: alice, shell: /bin/bash}
        - {name: bob}
    - name: Twice
      user: {name: "{{ item.name }}"}
      loop: [{name: a}, {name: a}]
    - name: Missing
      user: {name: "{{ item.name }}", shell: "{{ item.shell }}"}
      loop: [{name: a, shell: /bin/sh}, {name: b}]
    - name: Whole
      user: {name: "{{ item }}"}
      loop: [{name: a}]
    - name: Mode
      file: {path: "/srv/{{ item.name }}", state: directory, mode: "{{ item.mode }}"}
      loop: [{name: a, mode: "0755"}]
`)
	hcl := strings.Join(strings.Fields(string(res.HCL)), " ")
	for _, want := range []string{
		`for_each = { alice = { name = "alice" shell = "/bin/bash" } bob = { name = "bob" shell = "/bin/sh" } }`,
		`name = item.value.name shell = item.value.shell`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("no %s in:\n%s", want, res.HCL)
		}
	}
	want := map[string]string{
		"Twice":   `with name "a" twice`,
		"Missing": "item 2 doesn't have shell",
		"Whole":   "each whole item of the loop",
		"Mode":    "is not an octal mode",
	}
	if res.Converted != 1 || len(res.Review) != len(want) {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
	for _, r := range res.Review {
		if !strings.Contains(r.Reason, want[r.Task]) {
			t.Errorf("%s: %q, want it to say %q", r.Task, r.Reason, want[r.Task])
		}
	}
}

// In a role, a field can go anywhere, a path included, since every item
// is written in the task.
func TestLiteralMapLoopInRole(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"tasks/main.yml": "- name: Dirs\n  file: {path: \"/srv/{{ item.name }}\", state: directory}\n  with_items:\n    - {name: a}\n    - {name: b}\n",
	})
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	if main := string(res.Files["main.circuit.hcl"]); res.Converted != 1 || !strings.Contains(main, `path = "/srv/${item.value.name}"`) {
		t.Fatalf("converted %d, review %+v\n%s", res.Converted, res.Review, main)
	}
}

// An item's value can hold a role default, as security's sshd settings
// do. for_each is written in HCL then, with the default as a variable,
// and keyed by a field that's written out in every item.
func TestLiteralMapLoopTemplated(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"defaults/main.yml": "security_ssh_port: \"22\"\n",
		"tasks/main.yml": `- name: sshd
  lineinfile:
    dest: /etc/ssh/sshd_config
    regexp: "{{ item.regexp }}"
    line: "{{ item.line }}"
  with_items:
    - regexp: "^Port"
      line: "Port {{ security_ssh_port }}"
    - regexp: "^UseDNS"
      line: "UseDNS no"
- name: Keyed by a template
  user: {name: "{{ item.name }}"}
  loop:
    - name: "{{ security_ssh_port }}"
`,
	})
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	main := strings.Join(strings.Fields(string(res.Files["main.circuit.hcl"])), " ")
	if res.Converted != 1 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "no field every item has is written out") {
		t.Fatalf("converted %d, review %+v\n%s", res.Converted, res.Review, main)
	}
	for _, want := range []string{
		`"^Port" = { line = "Port ${var.security_ssh_port}", regexp = "^Port" }`,
		`"^UseDNS" = { line = "UseDNS no", regexp = "^UseDNS" }`,
	} {
		if !strings.Contains(main, want) {
			t.Errorf("no %s in:\n%s", want, main)
		}
	}
	if !strings.Contains(string(res.Files["variables.tf"]), `variable "security_ssh_port"`) {
		t.Errorf("no variable for the default:\n%s", res.Files["variables.tf"])
	}
}

// A field read with default(omit) is left out when an item doesn't have
// it, which is null in HCL, so the argument is unset. default(true),
// default(false) and default(N) are the text Ansible writes into the
// argument: True, False and the number.
func TestRoleLoopItemDefaults(t *testing.T) {
	for _, tc := range []struct {
		name, read, defaults string
		typ, item, review    string
	}{
		{name: "omit, item has it", read: "default(omit)", defaults: "[{name: a, shell: /bin/zsh}]",
			typ: "shell = optional(string)", item: `shell = "/bin/zsh"`},
		{name: "omit, item lacks it", read: "default(omit)", defaults: "[{name: a}]",
			typ: "shell = optional(string)", item: `{ name = "a" }`},
		{name: "true, item has it", read: "default(true)", defaults: "[{name: a, shell: /bin/zsh}]",
			typ: `shell = optional(string, "True")`, item: `shell = "/bin/zsh"`},
		{name: "true, item lacks it", read: "default(True)", defaults: "[{name: a}]",
			typ: `shell = optional(string, "True")`, item: `{ name = "a" }`},
		{name: "false", read: "default(false)", defaults: "[{name: a}]",
			typ: `shell = optional(string, "False")`},
		{name: "False", read: "default(False)", defaults: "[{name: a}]",
			typ: `shell = optional(string, "False")`},
		{name: "number", read: "default(007)", defaults: "[{name: a}]",
			typ: `shell = optional(string, "7")`},
		{name: "omit in part of the value", read: "default(omit) }}/x{{ ''", defaults: "[{name: a}]",
			review: "with default(omit) as part of its value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shell := "{{ item.shell | " + tc.read + " }}"
			if tc.review != "" {
				shell = "{{ item.shell | default(omit) }}/x"
			}
			res, err := ConvertRole(writeRole(t, map[string]string{
				"defaults/main.yml": "admins: " + tc.defaults + "\n",
				"tasks/main.yml":    "- name: Admins\n  user: {name: \"{{ item.name }}\", shell: \"" + shell + "\"}\n  loop: \"{{ admins }}\"\n",
			}))
			if err != nil {
				t.Fatal(err)
			}
			if tc.review != "" {
				if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, tc.review) {
					t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
				}
				return
			}
			flat := func(b []byte) string { return strings.Join(strings.Fields(string(b)), " ") }
			main, vars := flat(res.Files["main.circuit.hcl"]), flat(res.Files["variables.tf"])
			if res.Converted != 1 || !strings.Contains(main, "shell = item.value.shell") {
				t.Fatalf("converted %d, review %+v\n%s", res.Converted, res.Review, main)
			}
			for _, want := range []string{"type = list(object({ name = string, " + tc.typ + " }))", tc.item} {
				if !strings.Contains(vars, want) {
					t.Errorf("variables.tf has no %q:\n%s", want, vars)
				}
			}
		})
	}
}

// In a loop written in the task, an item with a default(omit) field
// converts, and one without it stays for review.
func TestLiteralMapLoopOmit(t *testing.T) {
	for _, tc := range []struct {
		name, loop, review string
	}{
		{name: "has it", loop: "[{name: a, shell: /bin/zsh}]"},
		{name: "lacks it", loop: "[{name: a}]", review: "item 1 doesn't have shell, which default(omit) leaves out"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := convertString(t, "- hosts: all\n  become: true\n  tasks:\n    - user: {name: \"{{ item.name }}\", shell: \"{{ item.shell | default(omit) }}\"}\n      loop: "+tc.loop+"\n")
			if tc.review == "" && (res.Converted != 1 || !strings.Contains(string(res.HCL), "item.value.shell")) {
				t.Fatalf("converted %d, review %+v\n%s", res.Converted, res.Review, res.HCL)
			}
			if tc.review != "" && (len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, tc.review)) {
				t.Fatalf("review %+v", res.Review)
			}
		})
	}
}
