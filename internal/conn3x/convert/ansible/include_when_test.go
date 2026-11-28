// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// An include_tasks tests its when once, before its tasks run. Any when the
// converter reads on a task, on what no step changes, inlines the file with
// the when ANDed onto each task's own. Anything else, or a when on a name
// an included task sets, keeps the include for review.
func TestIncludeTasksWhen(t *testing.T) {
	defaults := "a: true\nb: false\nlst: []\nmethod: pkg\n"
	probe := "- command: which php\n  changed_when: false\n  failed_when: false\n  register: p\n"
	stat := "- stat: {path: /etc/x}\n  register: out\n"
	for name, c := range map[string]struct {
		when, before, first, inner string
		want                       string // in main.circuit.hcl; "" means the include stays
	}{
		"or":            {when: "a or b", want: "when = (var.a) || (var.b)"},
		"not":           {when: "not a", want: "when = !var.a"},
		"length":        {when: "lst | length > 0", want: "when = length(var.lst) > 0"},
		"distribution":  {when: "ansible_facts.distribution == 'Ubuntu'", want: `when = try(var.hosts[each.key].os, data.conn3x_host.facts[each.key].os_id) == "ubuntu"`},
		"codename":      {when: "ansible_distribution_release == 'noble'", want: `when = data.conn3x_host.facts[each.key].os_codename == "noble"`},
		"service mgr":   {when: "ansible_facts.service_mgr == 'systemd'", want: `when = data.conn3x_host.facts[each.key].service_manager == "systemd"`},
		"text default":  {when: "method == 'pkg'", want: `when = var.method == "pkg"`},
		"list":          {when: "\n    - a | bool\n    - lst | length > 0", want: "when = var.a && length(var.lst) > 0"},
		"ANDs own when": {when: "a | bool", inner: "  when: not b\n", want: "when = !var.b && var.a"},
		"unreadable":    {when: "a is version('1', '>')"},
		"set_fact":      {when: "a | bool", inner: "- set_fact: {a: false}\n"},
		"probe":         {when: "p.rc != 0", before: probe, want: "when = data.conn3x_command.p[each.key].exit_code != 0"},
		"probe late":    {when: "p.rc != 0", before: "- package: {name: curl}\n" + probe, want: "__p[each.key].exit_code != 0"}, // only_if on the circuit's probe
		// A probe the include reads, registered again inside it.
		"register":     {when: "out.stat.exists", before: stat, first: stat},
		"no probe yet": {when: "out.stat.exists", first: stat},
	} {
		inner := c.first + "- name: Tools\n  package: {name: jq}\n" + c.inner
		res, err := ConvertRole(writeRole(t, map[string]string{
			"defaults/main.yml": defaults,
			"tasks/extra.yml":   inner,
			"tasks/main.yml":    c.before + "- include_tasks: extra.yml\n  when: " + c.when + "\n",
		}))
		if err != nil {
			t.Fatal(err)
		}
		hcl := string(res.Files["main.circuit.hcl"])
		if c.want == "" {
			if !strings.Contains(reasons(res), "uses include_tasks") || strings.Contains(hcl, `name = "jq"`) {
				t.Errorf("%s: kept? review %q\n%s", name, reasons(res), hcl)
			}
			continue
		}
		if !strings.Contains(hcl, c.want) || strings.Contains(reasons(res), "include_tasks") {
			t.Errorf("%s: no %q, review %q\n%s", name, c.want, reasons(res), hcl)
		}
	}
}

// The probe.go example: a read-only probe, then an include on its exit
// code. The probe is a data source, read once at plan, so the include's
// when reads the same on each included task as on the include.
func TestIncludeTasksOnProbe(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"tasks/main.yml": `- name: Check if PHP is installed.
  command: which php
  changed_when: false
  failed_when: false
  register: php_installed
- include_tasks: install-from-source.yml
  when: php_installed.rc != 0
`,
		"tasks/install-from-source.yml": "- name: Build tools\n  package: {name: gcc}\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	hcl := string(res.Files["main.circuit.hcl"])
	for _, want := range []string{`data "conn3x_command" "php_installed"`, "when = data.conn3x_command.php_installed[each.key].exit_code != 0", `name = "gcc"`} {
		if !strings.Contains(hcl, want) {
			t.Errorf("no %q\n%s", want, hcl)
		}
	}
	if len(res.Review) != 0 {
		t.Errorf("review %+v", res.Review)
	}
}
