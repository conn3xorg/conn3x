// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// A package task whose name is a role default that's a list installs
// each item, as a loop over the list would.
func TestPackageNameList(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"defaults/main.yml": "tools:\n  - git\n  - jq\n",
		"tasks/main.yml":    "- name: Tools\n  ansible.builtin.package:\n    name: \"{{ tools }}\"\n    state: present\n",
	})
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	main := strings.Join(strings.Fields(string(res.Files["main.circuit.hcl"])), " ")
	if res.Converted != 1 || len(res.Review) != 0 {
		t.Fatalf("converted %d, review %+v\n%s", res.Converted, res.Review, main)
	}
	if !strings.Contains(main, `for_each = var.tools package { name = item.value }`) {
		t.Errorf("want a step per item:\n%s", main)
	}
	if v := string(res.Files["variables.tf"]); !strings.Contains(v, `variable "tools"`) || !strings.Contains(v, `list(string)`) {
		t.Errorf("want a list variable:\n%s", v)
	}
}
