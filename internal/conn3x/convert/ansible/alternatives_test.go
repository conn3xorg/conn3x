// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertAlternatives(t *testing.T) {
	for task, want := range map[string][]string{
		"community.general.alternatives: { name: editor, path: /usr/bin/vim.basic }":                                  {"alternatives {", `name = "editor"`, `path = "/usr/bin/vim.basic"`},
		"alternatives: { name: java, path: /opt/jdk/bin/java, link: /usr/bin/java, priority: 2100, state: selected }": {`"/usr/bin/java"`, "priority = 2100"},
	} {
		res := convertString(t, "- hosts: all\n  become: true\n  tasks:\n    - "+task+"\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %v", task, res.Converted, res.Review)
		}
		for _, w := range want {
			if !strings.Contains(string(res.HCL), w) {
				t.Errorf("%s: missing %s:\n%s", task, w, res.HCL)
			}
		}
	}
	for task, reason := range map[string]string{
		"alternatives: { name: editor, path: /usr/bin/vim.basic, state: absent }":                                                                "no Conn3x equivalent",
		"alternatives: { name: editor, path: /usr/bin/vim.basic, state: auto }":                                                                  "no Conn3x equivalent",
		"alternatives: { name: editor, path: /usr/bin/vim.basic, subcommands: [{ name: view, path: /usr/bin/vim.basic, link: /usr/bin/view }] }": "slave links",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: %+v", task, res.Review)
		}
	}
}
