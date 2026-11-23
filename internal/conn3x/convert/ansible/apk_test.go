// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// community.general.apk becomes package steps, as apt and dnf do.
func TestConvertAPK(t *testing.T) {
	for task, want := range map[string][]string{
		"community.general.apk: {name: [tree, curl], state: present, no_cache: true}": {"package {", `name = "tree"`, `name = "curl"`},
		"community.general.apk: {name: nginx, state: latest, update_cache: true}":     {`name  = "nginx"`, `state = "latest"`, "update_cache dropped"},
		"apk: {name: tree, state: absent}":                                            {`state = "absent"`},
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
		"community.general.apk: {upgrade: true}":                                 "names no package",
		"community.general.apk: {name: tree, repository: 'https://example.com'}": "repository",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || !strings.Contains(reasons(res), reason) {
			t.Errorf("%s: converted %d, review %q, want %q", task, res.Converted, reasons(res), reason)
		}
	}
}
