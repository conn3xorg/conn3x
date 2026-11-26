// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// A service or package task's state, or a service's enabled, from a role
// default stays the variable when the default's own value is one the step
// takes, and a validation keeps a caller's to the same (#1436).
func TestRoleDefaultStateAndEnabled(t *testing.T) {
	const checkFirst = `refers to the role default "x", and the converter keeps a default as a variable only where Conn3x uses its value exactly as Ansible does`
	for _, c := range []struct {
		name, defaults, vars, task, review string
		want                               []string
	}{
		{name: "service started", defaults: "x: started", task: `service: {name: nginx, state: "{{ x }}"}`,
			want: []string{"state = var.x", `condition     = contains(["started", "stopped"], var.x)`, "restarted and reloaded are handler actions in Conn3x"}},
		{name: "service stopped", defaults: "x: stopped", task: `service: {name: nginx, state: "{{ x }}"}`, want: []string{"state = var.x"}},
		{name: "service restarted", defaults: "x: restarted", task: `service: {name: nginx, state: "{{ x }}"}`, review: "state " + checkFirst},
		{name: "service reloaded", defaults: "x: reloaded", task: `systemd: {name: nginx, state: "{{ x }}"}`, review: "state " + checkFirst},
		{name: "service expression", defaults: "x: started", task: `service: {name: nginx, state: "{{ x | lower }}"}`, review: "state uses a Jinja expression"},
		{name: "service set in vars", defaults: "x: started", vars: "x: stopped", task: `service: {name: nginx, state: "{{ x }}"}`, want: []string{`state = "stopped"`}},
		{name: "enabled bool", defaults: "x: yes", task: `service: {name: nginx, enabled: "{{ x }}"}`, want: []string{"enabled = var.x"}},
		{name: "enabled string", defaults: `x: "yes"`, task: `service: {name: nginx, enabled: "{{ x }}"}`, review: "enabled " + checkFirst},
		{name: "nginx shape", defaults: "x: started\ny: true", task: `service: {name: nginx, state: "{{ x }}", enabled: "{{ y }}"}`,
			want: []string{"state   = var.x", "enabled = var.y"}},
		{name: "package present", defaults: "x: present", task: `package: {name: nginx, state: "{{ x }}"}`,
			want: []string{`state = lookup({ installed = "present", removed = "absent" }, var.x, var.x)`, `contains(["present", "installed", "latest", "absent", "removed"], var.x)`}},
		{name: "package installed", defaults: "x: installed", task: `dnf: {name: nginx, state: "{{ x }}"}`, want: []string{"var.x, var.x)"}},
		{name: "package latest", defaults: "x: latest", task: `apt: {name: nginx, state: "{{ x }}"}`, want: []string{"var.x, var.x)"}},
		{name: "package absent", defaults: "x: absent", task: `yum: {name: nginx, state: "{{ x }}"}`, want: []string{"var.x, var.x)"}},
		{name: "package removed", defaults: "x: removed", task: `package: {name: nginx, state: "{{ x }}"}`, want: []string{"var.x, var.x)"}},
		{name: "package started", defaults: "x: started", task: `package: {name: nginx, state: "{{ x }}"}`, review: "state " + checkFirst},
		{name: "package file", defaults: "x: present", task: `dnf: {name: /tmp/app-1.0-1.x86_64.rpm, state: "{{ x }}"}`, review: "takes its state from a role default with a package file"},
	} {
		files := map[string]string{
			"defaults/main.yml": c.defaults + "\n",
			"tasks/main.yml":    "- name: t\n  " + c.task + "\n",
		}
		if c.vars != "" {
			files["vars/main.yml"] = c.vars + "\n"
		}
		res, err := ConvertRole(writeRole(t, files))
		if err != nil {
			t.Fatal(err)
		}
		hcl, vars := string(res.Files["main.circuit.hcl"]), string(res.Files["variables.tf"])
		if c.review != "" {
			if len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, c.review) || strings.Contains(vars, "contains([") {
				t.Errorf("%s: review %+v, want %q\n%s", c.name, res.Review, c.review, vars)
			}
			continue
		}
		if len(res.Review) != 0 {
			t.Errorf("%s: review %+v", c.name, res.Review)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(hcl+vars, w) {
				t.Errorf("%s: missing %q in\n%s\n%s", c.name, w, hcl, vars)
			}
		}
	}
}
