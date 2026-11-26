// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// A test of ansible_version reads as true or false only when every
// ansible-core from ansibleCoreFloor gives the same answer.
func TestFoldVersion(t *testing.T) {
	for _, tc := range []struct {
		cond, e string
		v       int
	}{
		{"ansible_version.full is version('2.12', '>=')", "", 1},
		{"ansible_version.full is version_compare('2.12', '<')", "", -1},
		{"ansible_version['full'] is version('2.16', 'ge')", "", 1},
		{"ansible_version.full is version('2.16', '<')", "", -1},
		{"ansible_version.full is version('2.16', '>')", "ansible_version.full is version('2.16', '>')", 0}, // 2.16 vs 2.16.0
		{"ansible_version.full is version('2.20', '>=')", "ansible_version.full is version('2.20', '>=')", 0},
		{"ansible_version.full is version('2.12')", "", -1},
		{"ansible_version.full is not version('2.12', '<')", "", 1},
		{"not ansible_version.full is version('2.12', '>=')", "", -1},
		{"ansible_version.full is version('2.12', '>=', strict=true)", "ansible_version.full is version('2.12', '>=', strict=true)", 0},
		{"ansible_version.major >= 2", "ansible_version.major >= 2", 0},
		{"x | bool and ansible_version.full is version('2.12', '>=') and ansible_facts.os_family in ['RedHat', 'Debian']", "x | bool and ansible_facts.os_family in ['RedHat', 'Debian']", 0},
		{"ansible_version.full is version('2.12', '<') or ansible_facts.os_family not in ['RedHat', 'Debian']", "ansible_facts.os_family not in ['RedHat', 'Debian']", 0},
		{"x and (ansible_version.full is version('2.12', '<') or y)", "x and y", 0},
		{"x and (ansible_version.full is version('2.12', '<') or y or z)", "x and (y or z)", 0},
		{"x or ansible_version.full is version('2.12', '>=')", "", 1},
	} {
		if e, v := foldVersion(tc.cond); e != tc.e || v != tc.v {
			t.Errorf("%s: got %q, %d; want %q, %d", tc.cond, e, v, tc.e, tc.v)
		}
	}
}

// geerlingguy.docker's install tasks come in pairs, one for Ansible
// before 2.12 and one from it: only the second converts, and the first
// never runs on a Debian or Red Hat family host.
func TestAnsibleVersionPairs(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"defaults/main.yml": "docker_install_compose_plugin: true\n",
		"tasks/main.yml": `- name: Old
  package: {name: docker-ce}
  when: "ansible_version.full is version_compare('2.12', '<') or ansible_facts.os_family not in ['RedHat', 'Debian']"
- name: New
  package: {name: docker-ce}
  when: "ansible_version.full is version_compare('2.12', '>=') and ansible_facts.os_family in ['RedHat', 'Debian']"
- name: Compose
  package: {name: docker-compose-plugin}
  when: "docker_install_compose_plugin | bool == true and ansible_version.full is version_compare('2.12', '>=') and ansible_facts.os_family in ['RedHat', 'Debian']"
- name: Off
  package: {name: docker-compose, state: absent}
  when: docker_install_compose_plugin | bool == false
- name: Newer
  package: {name: podman}
  when: ansible_version.full is version('2.20', '>=')
`,
	})
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.Converted != 3 || len(res.Review) != 2 || res.Review[0].Task != "Old" || res.Review[1].Reason != versionReason {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
	out := string(res.Files["main.circuit.hcl"])
	if !strings.Contains(out, "var.docker_install_compose_plugin\n") || !strings.Contains(out, "!var.docker_install_compose_plugin") {
		t.Errorf("want Compose on the variable alone and Off on its negation:\n%s", out)
	}
	if !strings.Contains(string(res.Files["README.md"]), "ansible-core from 2.16 on") {
		t.Errorf("README doesn't say which Ansible:\n%s", res.Files["README.md"])
	}
}
