// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// A per-OS default some release's vars file doesn't set converts. The step
// that reads it gets a precondition, so a host loading no such file stops
// at plan saying so, as Ansible stops on the undefined value, unless the
// caller sets the variable. The set_fact can be in an included file.
func TestDefaultMissingForSomeReleases(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"vars/Debian.yml":   "__app_service: app-deb\n",
		"vars/RedHat-9.yml": "__app_service: app-rh\n",
		"tasks/main.yml":    "- include_tasks: variables.yml\n- name: Running\n  service: {name: \"{{ app_service }}\", state: started}\n",
		"tasks/variables.yml": `- include_vars: "{{ item }}"
  with_first_found:
    - files:
        - "vars/{{ ansible_facts.os_family }}-{{ ansible_facts.distribution_major_version }}.yml"
        - "vars/{{ ansible_facts.os_family }}.yml"
      skip: true
- name: Define app_service.
  set_fact:
    app_service: "{{ __app_service }}"
  when: app_service is not defined
`,
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
		`name = var.app_service != null ? var.app_service :`,
		`precondition { condition = var.app_service != null || contains([`,
		`error_message = "${each.key} loads none of the role's vars files that set app_service, so Ansible would stop here too. Set var.app_service for it."`,
	} {
		if !strings.Contains(main, want) {
			t.Errorf("no %s in:\n%s", want, main)
		}
	}
	if !strings.Contains(string(res.Files["variables.tf"]), `variable "app_service"`) {
		t.Errorf("no variable for the default:\n%s", res.Files["variables.tf"])
	}
}
