// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"regexp"
	"strings"
	"testing"
)

// Text from a role goes into the circuit as HCL strings, so a ${ } or %{ }
// in it stays text: $${path.cwd}, never an expression the circuit runs on
// the controller. Here it's in a vars file's name and in a vars list item.
func TestRoleTextIsEscapedInHCL(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"vars/Debian.yml":       "__app_service: app-deb\n__app_packages:\n  - jq\n  - 'key${path.cwd}'\n  - 'tpl%{ if true }x%{ endif }'\n",
		"vars/RedHat.yml":       "__app_service: app-rh\n__app_packages:\n  - jq\n",
		"vars/RedHat-9.yml":     "__app_service: app-rh9\n__app_packages:\n  - jq\n",
		"vars/z${path.cwd}.yml": "unused: 1\n",
		"tasks/main.yml": `- include_vars: "{{ item }}"
  with_first_found:
    - files:
        - "vars/{{ ansible_facts.os_family }}-{{ ansible_facts.distribution_major_version }}.yml"
        - "vars/{{ ansible_facts.os_family }}.yml"
      skip: true
- name: Define app_service.
  set_fact:
    app_service: "{{ __app_service }}"
  when: app_service is not defined
- name: Define app_packages.
  set_fact:
    app_packages: "{{ __app_packages | list }}"
  when: app_packages is not defined
- name: Running
  service: {name: "{{ app_service }}", state: started}
- name: Install
  package:
    name: "{{ app_packages }}"
`,
	})
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	main := string(res.Files["main.circuit.hcl"])
	for _, want := range []string{`"z$${path.cwd}.yml"`, `"key$${path.cwd}"`, `"tpl%%{ if true }x%%{ endif }"`} {
		if !strings.Contains(main, want) {
			t.Errorf("no %s in:\n%s", want, main)
		}
	}
	// A live interpolation is ${ or %{ not preceded by its own escape.
	if live := regexp.MustCompile(`(^|[^$])\$\{path\.cwd\}|(^|[^%])%\{ if true`).FindString(main); live != "" {
		t.Errorf("role text left live in the circuit: %q", live)
	}
}
