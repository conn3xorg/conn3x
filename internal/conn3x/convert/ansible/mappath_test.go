// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// A field of a loop's items can go in a path, as a vhost's server_name
// does, when every item the role sets suits it; the variable checks the
// ones a caller sets.
func TestMapFieldInPath(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"defaults/main.yml":  "nginx_vhosts: []\nsites:\n  - {root: /srv/a, conf: a.conf}\n",
		"templates/vhost.j2": "server {}\n",
		"tasks/main.yml": `- name: Vhosts
  template: {src: vhost.j2, dest: "/etc/nginx/sites-enabled/{{ item.server_name }}.conf", mode: "0644"}
  with_items: "{{ nginx_vhosts }}"
- name: Roots
  file: {path: "{{ item.root }}", state: directory}
  loop: "{{ sites }}"
- name: Confs
  template: {src: vhost.j2, dest: "/etc/nginx/conf.d/{{ item.conf }}", mode: "0644"}
  loop: "{{ sites }}"
`,
	})
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	vars, circuit := string(res.Files["variables.tf"]), string(res.Files["main.circuit.hcl"])
	if res.Converted != 3 || len(res.Review) != 0 {
		t.Fatalf("converted %d, review %+v\n%s\n%s", res.Converted, res.Review, circuit, vars)
	}
	for _, want := range []string{
		`destination = "/etc/nginx/sites-enabled/${item.value.server_name}.conf"`,
		`for_each = { for i in var.nginx_vhosts : i.server_name => i }`,
	} {
		if !strings.Contains(circuit, want) {
			t.Errorf("circuit lacks %s:\n%s", want, circuit)
		}
	}
	for _, want := range []string{
		`alltrue([for i in var.sites : startswith(i.root, "/")])`,
		`alltrue([for i in var.sites : !endswith(i.conf, "/")])`,
	} {
		if !strings.Contains(vars, want) {
			t.Errorf("variables lack %s:\n%s", want, vars)
		}
	}
	if strings.Contains(vars, "i.server_name, \"/\"") {
		t.Errorf("server_name sits inside the path, so it needs no check:\n%s", vars)
	}
}

// An item the role sets that doesn't suit the path keeps the task for
// review, as a plain default would.
func TestMapFieldInPathRoleValue(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"defaults/main.yml": "sites:\n  - {root: srv/a}\n",
		"tasks/main.yml":    "- name: Roots\n  file: {path: \"{{ item.root }}\", state: directory}\n  loop: \"{{ sites }}\"\n",
	})
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, `uses item.root from the role default "sites" and would be`) {
		t.Fatalf("review %+v", res.Review)
	}
}
