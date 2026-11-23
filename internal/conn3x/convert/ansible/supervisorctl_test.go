// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// supervisorctl's states become a supervisor_program step; its actions,
// name: all, and an absent that Ansible would fail on stay for review.
func TestConvertSupervisorctl(t *testing.T) {
	for task, want := range map[string][]string{
		"community.general.supervisorctl: {name: app, state: started}":                         {"supervisor_program {", `name  = "app"`, `state = "started"`, "reread and add"},
		"supervisorctl: {name: app, state: stopped, config: /etc/supervisor/supervisord.conf}": {`state  = "stopped"`, `config = "/etc/supervisor/supervisord.conf"`},
		"supervisorctl: {name: 'workers:', state: present}":                                    {`name  = "workers:"`, `state = "present"`},
		"supervisorctl: {name: app, state: absent, stop_before_removing: true}":                {`state = "absent"`},
		"supervisorctl: {name: app, state: started, server_url: 'http://127.0.0.1:9001', username: admin, password: s3cret, supervisorctl_path: /usr/local/bin/supervisorctl, wait: true}": {
			`server_url         = "http://127.0.0.1:9001"`, `username           = "admin"`, `supervisorctl_path = "/usr/local/bin/supervisorctl"`, "TODO(convert): Set password", "wait dropped",
		},
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
		if strings.Contains(string(res.HCL), "s3cret") {
			t.Errorf("%s: the password was copied:\n%s", task, res.HCL)
		}
	}
	for task, reason := range map[string]string{
		"supervisorctl: {name: app, state: restarted}":                         "an action rather than a state",
		"supervisorctl: {name: app, state: signalled, signal: USR1}":           "an action rather than a state",
		"supervisorctl: {name: app, state: absent}":                            "without stop_before_removing",
		"supervisorctl: {name: all, state: started}":                           "name: all",
		"supervisorctl: {name: 'web:web_00', state: started}":                  "can't be a supervisor_program step",
		"supervisorctl: {name: app, state: started, config: supervisord.conf}": "must be an absolute path",
		"supervisorctl: {name: '{{ app_name }}', state: started}":              "variable",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || !strings.Contains(reasons(res), reason) {
			t.Errorf("%s: converted %d, review %q, want %q", task, res.Converted, reasons(res), reason)
		}
	}
}
