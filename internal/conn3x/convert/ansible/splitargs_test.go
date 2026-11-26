// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// A free-form line splits as Ansible's split_args splits it: not inside
// {{ }}, {% %}, {# #} or quotes. One Ansible would refuse, or that has an
// escape, isn't split here.
func TestSplitArgs(t *testing.T) {
	for line, want := range map[string][]string{
		"name={{ x }} state=started":        {"name={{ x }}", "state=started"},
		"name={{x}}":                        {"name={{x}}"},
		`name="a b" state=present`:          {`name="a b"`, "state=present"},
		"name='{{ x }}'":                    {"name='{{ x }}'"},
		"  name=a \t state=b\n":             {"name=a", "state=b"},
		"name={{ x | default('a b') }} y=1": {"name={{ x | default('a b') }}", "y=1"},
		"name={% if a %}b{% endif %} y=1":   {"name={% if a %}b{% endif %}", "y=1"},
		"name=a{# a note #} y=1":            {"name=a{# a note #}", "y=1"},
		`msg="it's {{ x }}" y=1`:            {`msg="it's {{ x }}"`, "y=1"},
		`regexp=^\s*a line="a b"`:           {`regexp=^\s*a`, `line="a b"`},
		"":                                  nil,
	} {
		got, ok := splitArgs(line)
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %q, %v", line, got, ok)
		}
	}
	for _, line := range []string{
		"name={{ x",
		"name=x }} y=1",
		"name={% if a",
		`name="a b`,
		"name='a",
		`line="a \"b\""`,
		`line=a\nb`,
		`a\=b=c`,
	} {
		if got, ok := splitArgs(line); ok {
			t.Errorf("%q: got %q, want no split", line, got)
		}
	}
}

// moduleOf reads a free-form line's values whole, without their outer
// quotes, and still marks the task as free-form (#1433).
func TestModuleOfFreeForm(t *testing.T) {
	for line, want := range map[string]map[string]string{
		"name={{ x }} state=started": {"name": "{{ x }}", "state": "started"},
		"name={{x}}":                 {"name": "{{x}}"},
		`name="a b" state=present`:   {"name": "a b", "state": "present"},
		"name='{{ x }}'":             {"name": "{{ x }}"},
		`name="" state=absent`:       {"name": "", "state": "absent"},
		// Unbalanced, it splits at each space, and the stray {{ keeps the
		// task for review.
		"name={{ x": {"name": "{{"},
	} {
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte("group: "+yamlQuote(line)+"\n"), &doc); err != nil {
			t.Fatal(err)
		}
		mod, args := moduleOf(mapping(doc.Content[0]))
		got := map[string]string{}
		for k, v := range args {
			if k != "_raw" {
				got[k] = v.Value
			}
		}
		if mod != "group" || !reflect.DeepEqual(got, want) || args["_raw"] == nil {
			t.Errorf("%q: %s %q, _raw %v", line, mod, got, args["_raw"] != nil)
		}
	}
}

// A free-form line with spaces inside {{ }} converts as the same line
// without them does; one left open stays for review.
func TestFreeFormJinjaWithSpaces(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"defaults/main.yml": "grp: app\n",
		"tasks/main.yml":    "- name: Spaced\n  group: \"name={{ grp }} state=present\"\n- name: Tight\n  group: \"name={{grp}} state=present\"\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	hcl := string(res.Files["main.circuit.hcl"])
	if res.Converted != 2 || len(res.Review) != 0 || strings.Count(hcl, "name = var.grp") != 2 {
		t.Errorf("converted %d, review %+v\n%s", res.Converted, res.Review, hcl)
	}

	res, err = ConvertRole(writeRole(t, map[string]string{
		"defaults/main.yml": "grp: app\n",
		"tasks/main.yml":    "- name: Open\n  group: \"name={{ grp state=present\"\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "uses a Jinja expression the converter can't translate") {
		t.Errorf("open: converted %d, review %+v", res.Converted, res.Review)
	}
}

// The free-form tasks of four Galaxy roles, reduced: none of them stays
// for review because the split broke the Jinja in name.
func TestFreeFormGalaxyTasks(t *testing.T) {
	hcl := map[string]string{}
	for role, files := range map[string]map[string]string{
		"geerlingguy.redis": {
			"tasks/main.yml":    "- name: Include OS-specific variables.\n  include_vars: \"{{ ansible_os_family }}.yml\"\n- name: Configure.\n  copy: {dest: /etc/redis.conf, content: x}\n  notify: restart redis\n",
			"handlers/main.yml": "---\n- name: restart redis\n  service: \"name={{ redis_daemon }} state=restarted\"\n",
			"vars/Debian.yml":   "redis_daemon: redis-server\n",
			"vars/RedHat.yml":   "redis_daemon: redis\n",
		},
		"geerlingguy.rabbitmq": {
			"defaults/main.yml": "rabbitmq_daemon: rabbitmq-server\n",
			"tasks/main.yml":    "- name: Configure.\n  copy: {dest: /etc/rabbitmq.conf, content: x}\n  notify: restart rabbitmq\n",
			"handlers/main.yml": "---\n- name: restart rabbitmq\n  service: \"name={{ rabbitmq_daemon }} state=restarted\"\n",
		},
		"geerlingguy.nfs": {
			"defaults/main.yml": "nfs_exports: []\n",
			"tasks/main.yml":    "- name: Include OS-specific variables.\n  include_vars: \"{{ ansible_os_family }}.yml\"\n- name: Ensure nfs is running.\n  service: \"name={{ nfs_server_daemon }} state=started enabled=yes\"\n  when: nfs_exports|length > 0\n",
			"vars/Debian.yml":   "nfs_server_daemon: nfs-kernel-server\n",
			"vars/RedHat.yml":   "nfs_server_daemon: nfs-server\n",
		},
		"geerlingguy.solr": {
			"defaults/main.yml": "solr_user: solr\nsolr_group: \"{{ solr_user }}\"\n",
			"tasks/main.yml":    "---\n- name: Ensure solr_group exists.\n  group: \"name={{ solr_group }} state=present\"\n",
		},
	} {
		res, err := ConvertRole(writeRole(t, files))
		if err != nil {
			t.Fatal(err)
		}
		hcl[role] = string(res.Files["main.circuit.hcl"])
		for _, r := range res.Review {
			if strings.Contains(r.Reason, "uses a Jinja expression the converter can't translate") {
				t.Errorf("%s: %s", role, r.Reason)
			}
		}
	}
	// The redis handler names its service per family, as the same handler
	// written as a mapping does.
	if want := `name   = { debian = "redis-server", redhat = "redis" }[local.os_family[each.key]]`; !strings.Contains(hcl["geerlingguy.redis"], want) {
		t.Errorf("redis: missing %s in\n%s", want, hcl["geerlingguy.redis"])
	}
}
