// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConvertRefusesWhatIsNotAPlaybook(t *testing.T) {
	dir := t.TempDir()
	if _, err := Convert(filepath.Join(dir, "missing.yml")); !os.IsNotExist(err) {
		t.Errorf("missing file: %v", err)
	}
	for name, src := range map[string]string{"map.yml": "hosts: all\n", "empty.yml": "", "bad.yml": "- [\n"} {
		p := filepath.Join(dir, name)
		writeFile(t, p, src)
		if _, err := Convert(p); err == nil || !strings.HasPrefix(err.Error(), p+": ") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A task whose result doesn't depend on who runs it converts even in a
// play that logs in as someone else.
func TestTasksSameForAnyUser(t *testing.T) {
	for _, task := range []string{
		"package: { name: tree }", "dnf: { name: tree }", "yum: { name: tree }", "apt: { name: tree }",
		"service: { name: a, state: started }", "systemd: { name: a, state: started }", "systemd_service: { name: a, enabled: yes }",
		"user: { name: a }", "group: { name: a }", "authorized_key: { user: a, key: 'ssh-ed25519 AAAA' }",
		"sysctl: { name: vm.swappiness, value: '10' }", "hostname: { name: web1 }", "timezone: { name: UTC }",
		"firewalld: { service: http, permanent: yes, immediate: yes }", "ufw: { rule: allow, port: '22' }",
		"seboolean: { name: a, state: yes, persistent: yes }", "sefcontext: { target: /srv, setype: t }",
		"selinux: { state: permissive }", "alternatives: { name: java, path: /usr/bin/java }", "snap: { name: lxd }",
		"mount: { path: /data, src: /dev/sdb1, fstype: xfs }", "cron: { name: j, job: /bin/true, user: app }",
	} {
		res := convertString(t, "- hosts: all\n  remote_user: deploy\n  tasks:\n    - "+task+"\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
	// The fact and debug modules are dropped with nothing to review.
	for _, task := range []string{"debug: { msg: hi }", "setup: {}", "service_facts: {}", "package_facts: {}"} {
		if res := convertString(t, "- hosts: all\n  remote_user: deploy\n  tasks:\n    - "+task+"\n"); len(res.Review) != 0 {
			t.Errorf("%s: review %+v", task, res.Review)
		}
	}
}

// Every way Ansible writes false turns become off, so become_user changes
// nothing; every way it writes true turns an option on.
func TestFalseAndTrueWords(t *testing.T) {
	for _, off := range []string{"'off'", "'n'", "'f'", "'0'", "'No'"} {
		res := convertString(t, "- hosts: all\n  become: "+off+"\n  become_user: postgres\n  tasks:\n    - copy: { dest: /a, content: x }\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("become: %s: converted %d, review %+v", off, res.Converted, res.Review)
		}
	}
	for _, on := range []string{"'on'", "'1'", "'y'", "'Yes'"} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - group: { name: a, system: "+on+" }\n")
		if !strings.Contains(string(res.HCL), "system = true") {
			t.Errorf("system: %s:\n%s", on, res.HCL)
		}
	}
	if res := convertString(t, "- hosts: all\n  tasks:\n    - group: { name: a, system: 'maybe' }\n"); !strings.Contains(string(res.HCL), "system = false") {
		t.Errorf("an unknown word is true:\n%s", res.HCL)
	}
}

func TestPlayVarsFilesNamedByJinja(t *testing.T) {
	res := convertString(t, "- hosts: all\n  vars_files: ['{{ env }}.yml']\n  tasks:\n    - copy: { dest: /a, content: x }\n")
	found := false
	for _, r := range res.Review {
		found = found || strings.Contains(r.Reason, "vars_files to a file named by a Jinja expression")
	}
	if !found {
		t.Errorf("review %+v", res.Review)
	}
}

func TestHandlerTaggedNever(t *testing.T) {
	res := convertString(t, "- hosts: all\n  tasks:\n    - copy: { dest: /a, content: x }\n      notify: restart\n  handlers:\n    - name: restart\n      service: { name: a, state: restarted }\n      tags: [never]\n")
	found := false
	for _, r := range res.Review {
		found = found || r.Reason == neverReason && r.Task == "restart"
	}
	if !found {
		t.Errorf("review %+v", res.Review)
	}
}

// With roles converted as circuits of their own, a play can't also batch.
func TestSerialWithRoleCalls(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"roles/web/tasks/main.yml": "- package: { name: nginx }\n",
		"site.yml":                 "- hosts: all\n  serial: 2\n  roles: [web]\n",
	})
	p := filepath.Join(dir, "site.yml")
	res, err := ConvertWith(p, Options{Roles: true})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range res.Review {
		found = found || strings.Contains(r.Reason, "sets serial and calls roles")
	}
	if !found {
		t.Errorf("review %+v", res.Review)
	}
}
