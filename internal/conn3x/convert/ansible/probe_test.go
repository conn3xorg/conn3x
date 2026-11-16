// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// A probe, a command with register and changed_when: false before any task
// changes the host, becomes a conn3x_command data source over the hosts,
// with a postcondition on its exit code unless the task allowed a failure,
// and the whens that read it become expressions on it.
func TestConvertRoleProbeGolden(t *testing.T) {
	res := goldenRole(t, "probe")
	if res.Converted != 5 || len(res.Review) != 0 {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
}

// What stays: a probe after a task that changes the host, one with a when,
// a shell probe, a second probe registering the same name, "is failed" on
// a probe with failed_when: false, and a when the converter can't read. A
// looped step's when still indexes the data source by the host.
func TestRoleProbeRefusals(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"tasks/main.yml": `- name: Which php
  command: which php
  changed_when: false
  failed_when: false
  register: php
- name: Shell probe
  shell: php -v | head -n 1
  changed_when: false
  register: php_v
- name: Where is nginx
  command: which nginx
  changed_when: false
  ignore_errors: true
  register: nginx
- name: Same name
  command: which nginx
  changed_when: false
  register: nginx
- name: Conditional probe
  command: which apache2
  changed_when: false
  register: apache
  when: php.rc == 0
- name: Looped
  package: { name: "{{ item }}" }
  with_items: [php-cli, php-fpm]
  when: "'/usr/bin/php' in php.stdout"
- name: Not for failed_when false
  file: { path: /etc/php-missing, state: touch }
  when: php is failed
- name: Nginx missing
  file: { path: /etc/nginx-missing, state: directory }
  when: nginx is failed
- name: Nginx line
  file: { path: /etc/nginx-there, state: directory }
  when:
    - nginx is succeeded
    - "'nginx' not in nginx.stdout"
- name: Unreadable
  file: { path: /etc/unread, state: directory }
  when: php.stdout_lines | length > 0
- name: Changes the host
  package: { name: curl }
- name: Late probe
  command: which curl
  changed_when: false
  register: curl
`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	hcl := string(res.Files["main.circuit.hcl"])
	for _, want := range []string{
		`data "conn3x_command" "php"`, `data "conn3x_command" "nginx"`,
		"for_each = [\"php-cli\", \"php-fpm\"]\n    when     = nonsensitive(strcontains(data.conn3x_command.php[each.key].stdout, \"/usr/bin/php\"))",
		"when = data.conn3x_command.nginx[each.key].exit_code != 0",
		`when = data.conn3x_command.nginx[each.key].exit_code == 0 && !nonsensitive(strcontains(data.conn3x_command.nginx[each.key].stdout, "nginx"))`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("missing %q:\n%s", want, hcl)
		}
	}
	if strings.Count(hcl, "postcondition") != 0 || strings.Contains(hcl, `"curl"`) && strings.Contains(hcl, "data \"conn3x_command\" \"curl\"") {
		t.Errorf("php and nginx allow a failure, and curl stays:\n%s", hcl)
	}
	var got []string
	for _, r := range res.Review {
		got = append(got, r.Task+": "+r.Reason)
	}
	for i, want := range []string{
		"Shell probe: uses changed_when",
		"Same name: registers nginx, which an earlier probe already registers",
		"Conditional probe: has a when, which the converter can't put on a probe yet",
		"Not for failed_when false: uses when",
		"Unreadable: uses when",
		"Late probe: probes the host after tasks that change it",
	} {
		if i >= len(got) || !strings.Contains(got[i], want) {
			t.Errorf("review %d: want %q in %q", i, want, got)
		}
	}
	if res.Converted != 6 || len(res.Review) != 6 {
		t.Errorf("converted %d, review %+v", res.Converted, res.Review)
	}
}

// A probe whose command a shell would read, or that fails other than as
// Ansible's false or true, or sets a keyword a data source can't carry,
// stays for review and says why.
func TestRoleProbeStays(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"tasks/main.yml": `- name: Piped
  command: php -v | head -n 1
  changed_when: false
  register: php_v
- name: Fails on text
  command: which php
  changed_when: false
  failed_when: "'error' in php.stderr"
  register: php
- name: Errors not ignored
  command: which nginx
  changed_when: false
  ignore_errors: false
  register: nginx
- name: Becomes
  command: which apache2
  changed_when: false
  become: true
  register: apache
`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(res.Files["main.circuit.hcl"]), "conn3x_command") {
		t.Errorf("no probe converts:\n%s", res.Files["main.circuit.hcl"])
	}
	var got []string
	for _, r := range res.Review {
		got = append(got, r.Task+": "+r.Reason)
	}
	for i, want := range []string{
		"Piped: uses characters a shell reads",
		"Fails on text: uses a failed_when other than false",
		"Errors not ignored: sets ignore_errors to something other than true",
		"Becomes: sets become on a probe, which the converter can't carry to a data source yet",
	} {
		if i >= len(got) || !strings.Contains(got[i], want) {
			t.Errorf("review %d: want %q in %q", i, want, got)
		}
	}
}
