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
