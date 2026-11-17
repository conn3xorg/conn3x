// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

const familyListInclude = `- include_vars: "{{ item }}"
  with_first_found:
    - files:
        - "vars/{{ ansible_facts.os_family }}-{{ ansible_facts.distribution_major_version }}.yml"
        - "vars/{{ ansible_facts.os_family }}.yml"
      skip: true
- name: Define app_packages.
  set_fact:
    app_packages: "{{ __app_packages | list }}"
  when: app_packages is not defined
- name: Install.
  package:
    name: "{{ app_packages }}"
`

// A list per OS from vars/ becomes a step per item, from the caller's list
// or the one the host's vars file sets, and a host whose file sets none
// stops at plan.
func TestFamilyListDefault(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"vars/Debian.yml":   "__app_packages:\n  - app\n  - app-doc\n",
		"vars/RedHat-9.yml": "__app_packages:\n  - app-rh\n",
		"tasks/main.yml":    familyListInclude,
	})
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	main := strings.Join(strings.Fields(string(res.Files["main.circuit.hcl"])), " ")
	if len(res.Review) != 0 {
		t.Fatalf("review %+v\n%s", res.Review, main)
	}
	for _, want := range []string{
		`for_each = var.app_packages != null ? var.app_packages : { "debian/Debian.yml" = ["app", "app-doc"], "redhat/RedHat-9.yml" = ["app-rh"] }[local.vars_file[each.key]]`,
		`name = item.value`,
		`precondition { condition = var.app_packages != null || contains(["debian/Debian.yml", "redhat/RedHat-9.yml"], local.vars_file[each.key])`,
	} {
		if !strings.Contains(main, want) {
			t.Errorf("no %s in:\n%s", want, main)
		}
	}
	vars := strings.Join(strings.Fields(string(res.Files["variables.tf"])), " ")
	if !strings.Contains(vars, `variable "app_packages" { type = list(string) default = null`) {
		t.Errorf("no list variable:\n%s", vars)
	}
}

// When a file only an include_vars the converter can't follow loads sets
// the list, a missing entry may not be a missing value, so the default
// stays for review.
func TestFamilyListDefaultUnfollowedInclude(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"vars/Debian.yml":   "__app_packages:\n  - app\n",
		"vars/RedHat-9.yml": "__app_packages:\n  - app-rh\n",
		"vars/Rocky.yml":    "__app_packages:\n  - app-rocky\n",
		"tasks/main.yml": strings.Replace(familyListInclude, "- name: Define app_packages.",
			"- include_vars: \"{{ lookup('env', 'APP_VARS') }}\"\n- name: Define app_packages.", 1),
	})
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(res.Files["main.circuit.hcl"]), "precondition") {
		t.Errorf("a gap trusted despite an include the converter doesn't follow:\n%s", res.Files["main.circuit.hcl"])
	}
}
