// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// community.general.zypper becomes package steps. Ansible's zypper leaves
// recommended packages out by default, so the step says so.
func TestConvertZypper(t *testing.T) {
	for task, want := range map[string][]string{
		"community.general.zypper: {name: [tree, curl], state: present}":             {`name               = "tree"`, `name               = "curl"`, "install_recommends = false"},
		"community.general.zypper: {name: nginx, disable_recommends: false}":         {"install_recommends = true"},
		"community.general.zypper: {name: nginx, state: latest, update_cache: true}": {`state              = "latest"`, "zypper refreshes"},
		"zypper: {name: tree, state: absent}":                                        {`state = "absent"`},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v\n%s", task, res.Converted, res.Review, res.HCL)
			continue
		}
		for _, w := range want {
			if !strings.Contains(string(res.HCL), w) {
				t.Errorf("%s: missing %q:\n%s", task, w, res.HCL)
			}
		}
	}
	for task, reason := range map[string]string{
		"community.general.zypper: {name: devel_basis, type: pattern}": "pattern",
		"community.general.zypper: {name: '*', state: dist-upgrade}":   "state",
		"community.general.zypper: {name: tree, oldpackage: true}":     "oldpackage",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || !strings.Contains(reasons(res), reason) {
			t.Errorf("%s: converted %d, review %q, want %q", task, res.Converted, reasons(res), reason)
		}
	}
}
