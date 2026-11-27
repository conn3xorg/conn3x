// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// A role's no_log task converts only when each value it passes is a role
// default that goes to a write-only argument; the variable is then
// sensitive, and ephemeral when nothing else reads it.
func TestNoLogRoleTask(t *testing.T) {
	const defaults = "mysql_root_password: changeme\napp_dir: /etc/app\n"
	for name, tc := range map[string]struct {
		task      string
		want      []string // in main.circuit.hcl; none means it stays for review
		reason    string
		ephemeral bool
	}{
		"copy": {
			task: "copy: {dest: /root/.pw, content: \"{{ mysql_root_password }}\", mode: \"0600\"}",
			want: []string{"content_wo = var.mysql_root_password", "From a no_log task: var.mysql_root_password reaches the host only through a write-only argument"}, ephemeral: true,
		},
		"mysql_user": {
			task: "mysql_user: {name: app, password: \"{{ mysql_root_password }}\"}",
			want: []string{"password_wo = var.mysql_root_password"}, ephemeral: true,
		},
		"postgresql_user": {
			task: "postgresql_user: {name: app, password: \"{{ mysql_root_password }}\"}",
			want: []string{"postgresql_role {", "password_wo = var.mysql_root_password"}, ephemeral: true,
		},
		"user hash": {
			task: "user: {name: app, password: \"{{ mysql_root_password }}\", update_password: on_create}",
			want: []string{"password_hash_wo   = var.mysql_root_password", "password_on_create = true"}, ephemeral: true,
		},
		"debconf password": {
			task: "debconf: {name: mysql-server, question: mysql-server/root_password, vtype: password, value: \"{{ mysql_root_password }}\"}",
			want: []string{"value_wo = var.mysql_root_password"}, ephemeral: true,
		},
		"template": {
			task: "template: {src: my.cnf.j2, dest: /root/.my.cnf, mode: \"0600\"}",
			want: []string{"mysql_root_password = var.mysql_root_password", "write_only = true"}, ephemeral: true,
		},
		"literal": {
			task:   "copy: {dest: /root/.pw, content: hunter2}",
			reason: "content a value written into the role",
		},
		"literal password": {
			task:   "mysql_user: {name: app, password: hunter2}",
			reason: "password a value written into the role",
		},
		"password expression": {
			task:   "mysql_user: {name: app, password: \"{{ mysql_root_password | default('hunter2') }}\"}",
			reason: "password an expression rather than one role default",
		},
		"no write-only form": {
			task:   "lineinfile: {path: /etc/app.conf, line: \"pw={{ mysql_root_password }}\"}",
			reason: "passes var.mysql_root_password to the line step's line, which has no write-only form",
		},
		"mixed": {
			task:   "copy: {dest: \"{{ app_dir }}/pw\", content: \"{{ mysql_root_password }}\"}",
			reason: "passes var.app_dir to the file step's path, which has no write-only form",
		},
		"not a default": {
			task:   "copy: {dest: /root/.pw, content: \"{{ lookup('env', 'PW') }}\"}",
			reason: "write them to this file", // not the converter's own reason, which could quote the value
		},
		"loop": {
			task:   "copy: {dest: \"/root/{{ item }}\", content: \"{{ mysql_root_password }}\"}\n  loop: [a, b]",
			reason: "write them to this file",
		},
		"when reads the secret": {
			task:   "copy: {dest: /root/.pw, content: \"{{ mysql_root_password }}\"}\n  when: mysql_root_password != \"changeme\"",
			reason: "tests var.mysql_root_password in when, which runs at plan time",
		},
		"when in a list reads the secret": {
			task:   "copy: {dest: /root/.pw, content: \"{{ mysql_root_password }}\"}\n  when:\n    - ansible_facts.os_family == \"Debian\"\n    - mysql_root_password | length > 0",
			reason: "tests var.mysql_root_password in when",
		},
		"when that doesn't read it": {
			task: "copy: {dest: /root/.pw, content: \"{{ mysql_root_password }}\", mode: \"0600\"}\n  when: ansible_facts.os_family == \"Debian\"",
			want: []string{"content_wo = var.mysql_root_password"}, ephemeral: true,
		},
		"nothing secret": {
			task:   "file: {path: /root/.pw, state: absent}",
			reason: "write them to this file",
		},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := ConvertRole(writeRole(t, map[string]string{
				"defaults/main.yml":   defaults,
				"templates/my.cnf.j2": "[client]\npassword={{ mysql_root_password }}\n",
				"tasks/main.yml":      "- name: secret\n  no_log: true\n  " + tc.task + "\n",
			}))
			if err != nil {
				t.Fatal(err)
			}
			hcl, vars := string(res.Files["main.circuit.hcl"]), string(res.Files["variables.tf"])
			if strings.Contains(hcl, "hunter2") || strings.Contains(hcl, "changeme") || len(res.Review) > 0 && strings.Contains(res.Review[0].Reason, "hunter2") {
				t.Fatalf("a secret reached the circuit:\n%s", hcl)
			}
			if tc.want == nil {
				if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, tc.reason) {
					t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
				}
				if strings.Contains(vars, "sensitive") {
					t.Fatalf("a variable turned sensitive for a task left for review:\n%s", vars)
				}
				return
			}
			if res.Converted != 1 || len(res.Review) != 0 || len(res.Notes) != 0 {
				t.Fatalf("converted %d, review %+v, notes %+v\n%s", res.Converted, res.Review, res.Notes, hcl)
			}
			for _, w := range tc.want {
				if !strings.Contains(hcl, w) {
					t.Errorf("missing %q:\n%s", w, hcl)
				}
			}
			v := vars[strings.Index(vars, `variable "mysql_root_password"`):]
			v = v[:strings.Index(v, "\n}")]
			if !strings.Contains(v, "sensitive   = true") || strings.Contains(v, "ephemeral") != tc.ephemeral {
				t.Errorf("variable:\n%s", v)
			}
		})
	}
}

// A variable a no_log task protects, but another task reads openly, stays
// sensitive without being ephemeral, which would refuse that other use.
func TestNoLogSharedVariable(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"defaults/main.yml": "app_token: changeme\n",
		"tasks/main.yml": `- name: secret
  no_log: true
  copy: {dest: /root/.token, content: "{{ app_token }}"}
- name: open
  copy: {dest: /etc/app.conf, content: "{{ app_token }}"}
`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	vars := string(res.Files["variables.tf"])
	if res.Converted != 2 || !strings.Contains(vars, "sensitive   = true") || strings.Contains(vars, "ephemeral") {
		t.Errorf("converted %d:\n%s", res.Converted, vars)
	}
}
