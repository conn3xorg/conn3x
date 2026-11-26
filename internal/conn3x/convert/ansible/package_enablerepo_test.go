// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// An enablerepo from a role default, bare or through default(omit) with or
// without true, follows the variable, as none when it's ""; package reads
// enablerepo only on a task for Red Hat family hosts alone (#1437).
func TestRoleEnablerepoDefault(t *testing.T) {
	const expr = `enable_repositories = var.x == "" ? null : [for id in split(",", var.x) : trimspace(id)]`
	const redhat = "\n  when: ansible_os_family == 'RedHat'"
	for _, c := range []struct {
		name, defaults, task, review string
		want                         []string
	}{
		{name: "package omit true empty", defaults: `x: ""`, task: `package: {name: git, enablerepo: "{{ x | default(omit, true) }}"}` + redhat,
			want: []string{expr, `default     = ""`, `when = local.os_family[each.key] == "redhat"`}},
		{name: "package omit true epel", defaults: "x: epel", task: `package: {name: redis, enablerepo: "{{ x | default(omit, true) }}"}` + redhat,
			want: []string{expr, `default     = "epel"`}},
		{name: "yum omit true empty", defaults: `x: ""`, task: `yum: {name: postgresql, enablerepo: "{{ x | default(omit, true) }}"}`, want: []string{expr}},
		{name: "yum omit true two", defaults: "x: 'epel, crb'", task: `yum: {name: postgresql, enablerepo: "{{x|default(omit,True)}}"}`, want: []string{expr}},
		{name: "dnf omit", defaults: "x: crb", task: `dnf: {name: nasm, enablerepo: "{{ x | default(omit) }}"}`, want: []string{expr}},
		{name: "dnf omit false", defaults: "x: crb", task: `dnf: {name: nasm, enablerepo: "{{ x | default(omit, false) }}"}`, want: []string{expr}},
		{name: "dnf bare", defaults: "x: crb", task: `dnf: {name: nasm, enablerepo: "{{ x }}"}`, want: []string{expr}},
		{name: "package literal", defaults: "x: crb", task: "package: {name: nasm, enablerepo: crb}" + redhat, want: []string{`enable_repositories = ["crb"]`}},
		{name: "package everywhere", defaults: `x: ""`, task: `package: {name: git, enablerepo: "{{ x | default(omit, true) }}"}`, review: "apt would stop on it"},
		{name: "package on Debian", defaults: `x: ""`, task: `package: {name: git, enablerepo: "{{ x | default(omit, true) }}"}` + "\n  when: ansible_os_family == 'Debian'", review: "apt would stop on it"},
		{name: "bool default", defaults: "x: false", task: `dnf: {name: git, enablerepo: "{{ x | default(omit, true) }}"}`, review: "which is a number or true or false"},
		{name: "glob default", defaults: "x: 'epel*'", task: `dnf: {name: git, enablerepo: "{{ x | default(omit, true) }}"}`, review: `repository ID "epel*" is not valid: use letters, digits and - _ . : only, from the role default "x"`},
		{name: "other default", defaults: "x: crb", task: `dnf: {name: git, enablerepo: "{{ x | default('epel') }}"}`, review: "enablerepo uses a Jinja expression"},
		{name: "not a default", defaults: "x: crb", task: `dnf: {name: git, enablerepo: "{{ y | default(omit, true) }}"}`, review: "enablerepo uses a Jinja expression"},
	} {
		res, err := ConvertRole(writeRole(t, map[string]string{
			"defaults/main.yml": c.defaults + "\n",
			"tasks/main.yml":    "- name: t\n  " + c.task + "\n",
		}))
		if err != nil {
			t.Fatal(err)
		}
		hcl, vars := string(res.Files["main.circuit.hcl"]), string(res.Files["variables.tf"])
		if c.review != "" {
			if len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, c.review) {
				t.Errorf("%s: review %+v, want %q", c.name, res.Review, c.review)
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

func TestOmitDefault(t *testing.T) {
	for in, want := range map[string]string{
		"{{ x | default(omit) }}":             "x",
		"{{ x | default(omit, true) }}":       "x",
		"{{x|default(omit,True)}}":            "x",
		" {{ x | default( omit , false ) }} ": "x",
		"{{ x }}":                             "",
		"{{ x | default('epel') }}":           "",
		"{{ x | default(omit, 'y') }}":        "",
		"{{ x | default(omit) | lower }}":     "",
		"{{ x | d(omit) }}":                   "",
		"{{ item.r | default(omit) }}":        "",
		"{{ x | default(omit) }}-y":           "",
		"{{ x }} {{ y | default(omit) }}":     "",
	} {
		got, ok := omitDefault(in)
		if got != want || ok != (want != "") {
			t.Errorf("omitDefault(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}
