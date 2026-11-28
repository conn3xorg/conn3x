// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"regexp"
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

// What stays: a probe that can fail after a task that changes the host,
// one with a when, a shell probe, a second probe registering the same name
// and the whens after it, though not those before, "is failed" on a probe with failed_when: false,
// and a when the converter can't read. A looped step's when still indexes
// the data source by the host.
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
- name: Where is git
  command: which git
  changed_when: false
  failed_when: false
  register: dup
- name: Before the second
  file: { path: /etc/git-first, state: directory }
  when: dup.rc != 0
- name: Same name
  command: which git
  changed_when: false
  failed_when: false
  register: dup
- name: Reads the second
  file: { path: /etc/git-missing, state: directory }
  when: dup.rc != 0
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
		"Conditional probe: has a when, and Ansible stops the play when it exits non-zero",
		"Not for failed_when false: uses when",
		"Unreadable: uses when",
		"Same name: registers dup, which an earlier probe already registers",
		"Reads the second: uses when",
		"Late probe: probes the host after tasks that change it, and Ansible stops the play when it exits non-zero",
	} {
		if i >= len(got) || !strings.Contains(got[i], want) {
			t.Errorf("review %d: want %q in %q", i, want, got)
		}
	}
	if !strings.Contains(hcl, "only_if = data.conn3x_command.n_") || strings.Count(hcl, "__dup[each.key].exit_code != 0") != 1 {
		t.Errorf("the when before the second dup reads the first, and none after it:\n%s", hcl)
	}
	if res.Converted != 8 || len(res.Review) != 7 {
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

// A probe after a task that changes the host becomes the circuit's probe
// block, and a when on it only_if, beside the when on what the plan knows.
// R is changed, where only that reads R, becomes triggers on R's step's
// revision in a command step. Each gated or triggered command gets a note.
func TestRoleProbeAfterChanges(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"defaults/main.yml": "flag: true\n",
		"tasks/main.yml": `- name: Changes the host
  package: { name: curl }
- name: Which php
  command: which php
  changed_when: false
  failed_when: false
  register: php
  when: flag | bool
- name: Has conf
  stat: { path: /etc/app.conf }
  register: conf
- name: Gated build
  command: /usr/local/bin/build
  when:
    - php.rc != 0
    - flag | bool
- name: Guarded build
  command: /usr/local/bin/build
  args: { creates: /usr/local/bin/php }
  when: php.rc != 0 and ansible_facts.os_family == 'Debian'
- name: Either
  file: { path: /etc/either, state: directory }
  when: not conf.stat.exists or flag | bool
- name: Succeeded on a guarded probe
  file: { path: /etc/ok, state: directory }
  when: php is succeeded
- name: Make it
  shell: fallocate -l 1M /swapfile
  args: { creates: /swapfile }
  register: made
- name: Format it
  command: mkswap /swapfile
  when: made is changed
- name: Touch it
  file: { path: /swapfile, state: touch }
  when: made.changed
`,
		"handlers/main.yml": `- name: restart app
  service: { name: app, state: restarted }
  when: php.rc == 0
`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	hcl := string(res.Files["main.circuit.hcl"])
	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`probe "php" \{\n    command = "which php"\n  \}`),
		regexp.MustCompile(`probe "conf" \{\n    command = "\[ -e '/etc/app.conf' \] \|\| \[ -L '/etc/app.conf' \]"\n  \}`),
		regexp.MustCompile(`only_if gates this command.*\n  step "gated_build" \{\n    when    = var.flag\n    only_if = data.conn3x_command.n_\d+__php\[each.key\].exit_code != 0\n    command \{\n      command = "/usr/local/bin/build"\n    \}`),
		regexp.MustCompile(`step "guarded_build" \{\n    when    = local.os_family\[each.key\] == "debian"\n    only_if = data.conn3x_command.n_\d+__php\[each.key\].exit_code != 0\n`),
		regexp.MustCompile(`only_if = \(!\(data.conn3x_command.n_\d+__conf\[each.key\].exit_code == 0\)\) \|\| \(var.flag\)`),
		regexp.MustCompile(`triggers runs this command.*\n  step "format_it" \{\n    command \{\n      command  = "mkswap /swapfile"\n      triggers = \[conn3x_command.n_\d+__make_it\[each.key\].revision\]`),
	} {
		if !want.MatchString(hcl) {
			t.Errorf("missing %s:\n%s", want, hcl)
		}
	}
	if strings.Contains(hcl, "data \"conn3x_command\"") || strings.Count(hcl, "TODO(convert): only_if gates") != 1 {
		t.Errorf("a late probe became a data source, or the guarded build got a note:\n%s", hcl)
	}
	got := reasons(res)
	for _, want := range []string{
		"is a handler with a when the converter can't translate yet",
		"uses when, which the converter can't translate yet",
		"reads whether made changed, which a circuit follows only in a command step's triggers",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("review: want %q in %q", want, got)
		}
	}
	if len(res.Review) != 3 {
		t.Errorf("review %+v", res.Review)
	}
}
