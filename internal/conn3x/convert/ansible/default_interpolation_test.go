// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// A default built from others with {{ name }} becomes a nullable variable
// and a local that builds it, which steps read. Anything more stays fixed.
func TestDefaultInterpolation(t *testing.T) {
	const install = "- name: Install\n  package: {name: \"{{ pkg }}\"}\n"
	for _, tc := range []struct {
		name, defaults string
		want           []string // in main.circuit.hcl and variables.tf, spaces folded; nil when it stays
	}{
		{"scalar", "ver: '1.2'\npkg: \"app-{{ ver }}\"\n", []string{
			`name = local.pkg`,
			`variable "pkg" { type = string default = null`,
			`pkg = var.pkg != null ? var.pkg : "app-${var.ver}"`,
			`condition = !strcontains(var.ver, ",")`,
			`condition = var.pkg == null || !strcontains(var.pkg, ",")`,
		}},
		{"list", "edition: ce\npkg:\n  - \"docker-{{ edition }}\"\n  - \"docker-{{edition}}-cli\"\n  - containerd.io\n", []string{
			`for_each = local.pkg package { name = item.value }`,
			`variable "pkg" { type = list(string) default = null`,
			`pkg = var.pkg != null ? var.pkg : [ "docker-${var.edition}", "docker-${var.edition}-cli", "containerd.io", ]`,
			`condition = !strcontains(var.edition, ",")`,
		}},
		{"chain", "pkg: \"{{ b }}-x\"\nb: \"{{ c }}-y\"\nc: z\n", []string{
			`name = local.pkg`,
			`pkg = var.pkg != null ? var.pkg : "${local.b}-x"`,
			`b = var.b != null ? var.b : "${var.c}-y"`,
			`condition = !strcontains(var.c, ",")`,
		}},
		{"escape", "ver: v1\npkg: \"${x}%{y}-{{ ver }}\"\n", []string{
			`pkg = var.pkg != null ? var.pkg : "$${x}%%{y}-${var.ver}"`,
		}},
		{"filter", "ver: V1\npkg: \"app-{{ ver | lower }}\"\n", nil},
		{"cycle", "pkg: \"{{ b }}\"\nb: \"{{ pkg }}-x\"\n", nil},
		{"self", "pkg: \"x-{{ pkg }}\"\n", nil},
		{"fact", "pkg: \"app-{{ ansible_facts.architecture }}\"\n", nil},
		{"bool", "on_: true\npkg: \"app-{{ on_ }}\"\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ConvertRole(writeRole(t, map[string]string{"defaults/main.yml": tc.defaults, "tasks/main.yml": install}))
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == nil {
				v := string(res.Files["variables.tf"])
				if len(res.Review) != 1 || !strings.Contains(v, `Default "pkg" (defaults/main.yml line `) || !strings.Contains(v, "is a Jinja expression, which the converter can't carry over") || strings.Contains(v, "locals") {
					t.Errorf("review %+v, want it to stay:\n%s", res.Review, v)
				}
				return
			}
			if len(res.Review) != 0 {
				t.Fatalf("review %+v", res.Review)
			}
			got := strings.Join(strings.Fields(string(res.Files["main.circuit.hcl"])+string(res.Files["variables.tf"])), " ")
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("want %s in:\n%s", w, got)
				}
			}
		})
	}
}

// A default built from others can't go in a path: a validation on its
// variable can't check the value its local builds.
func TestDefaultInterpolationPath(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"defaults/main.yml": "name: app\ndir: \"/opt/{{ name }}\"\n",
		"tasks/main.yml":    "- name: Dir\n  file: {path: \"{{ dir }}\", state: directory}\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, `path refers to the role default "dir", which is built from other defaults`) {
		t.Errorf("review %+v", res.Review)
	}
}
