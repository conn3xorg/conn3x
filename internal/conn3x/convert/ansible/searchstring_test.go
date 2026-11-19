// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// lineinfile's search_string is literal text, so it becomes the step's
// regexp once quoted; the step already matches, adds and removes the way
// the module does.
func TestConvertLineinfileSearchString(t *testing.T) {
	for task, want := range map[string][]string{
		"lineinfile: { path: /etc/a, search_string: 'Port 22', line: 'Port 2222' }":            {`regexp = "Port 22"`, `line = "Port 2222"`},
		"lineinfile: { path: /etc/a, search_string: '127.0.0.1', line: x }":                    {`regexp = "127\\.0\\.0\\.1"`},
		"lineinfile: { path: /etc/a, search_string: 'Port 22', state: absent }":                {`regexp = "Port 22"`, `state = "absent"`},
		"lineinfile: { path: /etc/a, search_string: 'a.b+c', line: x, insertafter: '^# net' }": {`regexp = "a\\.b\\+c"`, `insert_after = "^# net"`},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
			continue
		}
		// Attributes are column-aligned, so compare with the runs of
		// spaces collapsed.
		hcl := strings.Join(strings.Fields(string(res.HCL)), " ")
		for _, w := range want {
			if !strings.Contains(hcl, w) {
				t.Errorf("%s: missing %q:\n%s", task, w, res.HCL)
			}
		}
	}
}

// What quoting can't settle, or Ansible itself refuses, stays for review.
func TestConvertLineinfileSearchStringRefusals(t *testing.T) {
	for task, reason := range map[string]string{
		"lineinfile: { path: /etc/a, search_string: 'Port {{ port }}', line: x }":                `refers to "port"`,
		"lineinfile: { path: /etc/a, search_string: 'a {{ 1 + 1 }} b', line: x }":                "uses a Jinja expression",
		"lineinfile: { path: /etc/a, search_string: 'Port 22', regexp: '^Port', line: x }":       "both search_string and regexp",
		"lineinfile: { path: /etc/a, search_string: '', line: x }":                               "empty search_string",
		`lineinfile: { path: /etc/a, search_string: "a\nb", line: x }`:                           "line break",
		"lineinfile: { path: /etc/a, search_string: 'a {# note #} b', line: x }":                 "Jinja comment",
		"lineinfile: { path: /etc/a, search_string: yes, line: x }":                              "quote it in the playbook",
		"lineinfile: { path: /etc/a, search_string: 'Port 22', regexp: '^Port', backrefs: yes }": "both search_string and regexp or backrefs",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, reason)
		}
	}
}
