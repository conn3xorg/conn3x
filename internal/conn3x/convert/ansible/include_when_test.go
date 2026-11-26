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
	for name, c := range map[string]struct {
		when, first, inner string
		want               string // in main.circuit.hcl; "" means the include stays
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
		"register":      {when: "out.stat.exists", first: "- stat: {path: /etc/x}\n  register: out\n"},
	} {
		inner := c.first + "- name: Tools\n  package: {name: jq}\n" + c.inner
		res, err := ConvertRole(writeRole(t, map[string]string{
			"defaults/main.yml": defaults,
			"tasks/extra.yml":   inner,
			"tasks/main.yml":    "- include_tasks: extra.yml\n  when: " + c.when + "\n",
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
