// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// Each module converts to its step with the arguments it maps, or stays
// for review saying why.
func TestConvertModuleArguments(t *testing.T) {
	for task, want := range map[string][]string{
		"blockinfile: { path: /etc/hosts, block: '10.0.0.1 db', insertafter: EOF, create: yes }": {
			"block {", `content      = "10.0.0.1 db"`, `marker       = "# {mark} ANSIBLE MANAGED BLOCK"`, `insert_after = "EOF"`, "create       = true", "Keeps Ansible's marker"},
		"blockinfile: { path: /etc/hosts, block: x, marker: '## {mark} app', state: absent }":          {`marker  = "## {mark} app"`, `state   = "absent"`},
		"community.general.ufw: { rule: allow, port: '22', proto: tcp, from_ip: 10.0.0.0/8 }":          {"ufw {", `action = "allow"`, `port   = "22/tcp"`, `from   = "10.0.0.0/8"`},
		"community.crypto.openssh_keypair: { path: /root/.ssh/id_ed25519, type: ed25519, size: 4096 }": {"ssh_keypair {", `type = "ed25519"`},
		"openssh_keypair: { path: /home/d/.ssh/id_rsa, owner: d, comment: d@web1 }":                    {`type    = "rsa"`, "bits    = 4096", `owner   = "d"`, `comment = "d@web1"`},
		"openssh_keypair: { path: /k, type: ecdsa, size: 384, mode: '0600' }":                          {"bits = 384"},
		"blockinfile: { path: /etc/hosts, block: x, marker_begin: START, marker_end: STOP }":           {"marker_begin", `"START"`, "marker_end", `"STOP"`},
		"win_share: { name: data, path: 'C:\\data', full: 'Administrators,DOMAIN\\ops', read: 'Everyone, administrators' }": {
			`full_access   = ["Administrators", "DOMAIN\\ops"]`, "change_access = []", `read_access   = ["Everyone"]`, `description   = ""`},
		"win_share: { name: data, path: 'C:\\data' }":                                                                                       {"full_access   = []", "read_access   = []"},
		"community.general.seport: { ports: 8081, proto: tcp, setype: http_port_t }":                                                        {"selinux_port {", `port     = "8081"`, `protocol = "tcp"`, `setype   = "http_port_t"`},
		"seport: { ports: ['8443-8450'], proto: tcp, setype: http_port_t, local: yes }":                                                     {`port     = "8443-8450"`},
		"community.general.xml: { path: /etc/app.xml, xpath: /a/b, value: '1' }":                                                            {"xml_value {", `xpath = "/a/b"`, `value = "1"`},
		"xml: { path: /etc/app.xml, xpath: \"/a/b[@id='x']\", attribute: mode, value: fast }":                                               {`xpath = "/a/b[@id='x']/@mode"`},
		"xml: { path: /etc/app.xml, xpath: /a/b/@old, state: absent }":                                                                      {`xpath = "/a/b/@old"`, `state = "absent"`},
		"ufw: { rule: deny, port: '53', proto: any }":                                                                                       {`port   = "53"`},
		"seboolean: { name: httpd_can_network_connect, state: yes, persistent: yes }":                                                       {"selinux_boolean {", "value = true"},
		"sefcontext: { target: '/srv/www(/.*)?', setype: httpd_sys_content_t }":                                                             {"selinux_fcontext {", `setype = "httpd_sys_content_t"`},
		"community.general.parted: { device: /dev/sdb, number: 1, state: present, part_start: 1MiB }":                                       {"partition {", `start  = "1MiB"`, `end    = "100%"`, `label  = "msdos"`},
		"parted: { device: /dev/sdb, number: 2, state: present, part_start: 1GiB, part_end: 20GiB, label: gpt, flags: [lvm], resize: yes }": {`label  = "gpt"`, `flags  = ["lvm"]`, "resize = true"},
		"get_url: { url: 'https://example.com/a.tgz', dest: /tmp/a.tgz, checksum: 'sha256:abc', mode: '0644' }": {
			"download {", `sha256 = "abc"`, `mode   = "0644"`},
		"unarchive: { src: /tmp/a.tgz, dest: /opt, remote_src: yes, creates: /opt/a }": {"archive {", `creates = "/opt/a"`},
		"git: { repo: 'https://example.com/r.git', dest: /opt/r, version: v1 }":        {"git {", `ref  = "v1"`},
		"ansible.posix.mount: { path: /data, src: /dev/sdb1, fstype: xfs, opts: noatime, state: mounted }": {
			"mount {", `fstype = "xfs"`, `opts   = "noatime"`},
		"user: { name: app, uid: 1500, group: app, groups: [web, log], home: /srv/app, shell: /bin/sh, system: yes }": {
			"user {", "uid    = 1500", `groups = ["web", "log"]`, `home   = "/srv/app"`, "system = true"},
		"group: { name: app, gid: 1500, system: no }":               {"group {", "gid    = 1500", "system = false"},
		"sysctl: { name: vm.swappiness, value: '10', reload: yes }": {"sysctl {", `value = "10"`},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		hcl := string(res.HCL)
		if res.Converted != 1 {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
			continue
		}
		for _, w := range want {
			if !strings.Contains(hcl, w) {
				t.Errorf("%s: missing %q:\n%s", task, w, hcl)
			}
		}
	}

	for task, reason := range map[string]string{
		"openssh_keypair: { path: /k, passphrase: hunter2 }":                                            "sets a passphrase",
		"openssh_keypair: { path: /k, type: rsa, size: 2048 }":                                          "2048-bit rsa key",
		"openssh_keypair: { path: /k, type: dsa }":                                                      "makes a dsa key",
		"openssh_keypair: { path: /k, regenerate: always }":                                             "regenerate: always",
		"openssh_keypair: { path: /k, force: yes }":                                                     "sets force",
		"openssh_keypair: { path: /k, private_key_format: pkcs8 }":                                      "private_key_format: pkcs8",
		"openssh_keypair: { path: /k, mode: '0644' }":                                                   "sets mode 0644",
		"win_share: { name: d, path: 'C:\\d', deny: Guests }":                                           "sets deny entries",
		"win_share: { name: d, path: 'C:\\d', rule_action: add }":                                       "rule_action: add",
		"win_share: { name: d, path: 'C:\\d', list: yes }":                                              "access-based enumeration off",
		"win_share: { name: d, path: 'C:\\d', caching_mode: None }":                                     "caching_mode None",
		"win_share: { name: d, path: 'C:\\d', encrypt: yes }":                                           "sets encrypt",
		"win_share: { name: d, path: 'C:\\d', state: absent }":                                          "absent",
		"seport: { ports: '8081,8082', proto: tcp, setype: http_port_t }":                               "names 2 ports",
		"seport: { ports: 8081, proto: tcp, setype: http_port_t, state: absent }":                       "absent",
		"xml: { path: /a.xml, xpath: /x:a, namespaces: { x: 'http://x' }, value: '1' }":                 "sets namespaces",
		"xml: { path: /a.xml, xpath: '//b', value: '1' }":                                               "xpath an xml_value step can't read",
		"xml: { path: /a.xml, xpath: /a, pretty_print: yes, value: '1' }":                               "sets pretty_print",
		"xml: { path: /a.xml, xpath: /a, count: yes }":                                                  "sets count",
		"xml: { path: /a.xml, xpath: /a/b }":                                                            "sets no value",
		"ufw: { state: enabled }":                                                                       "changes ufw itself",
		"seboolean: { name: httpd_can_network_connect, state: yes }":                                    "until reboot only",
		"get_url: { url: 'https://example.com/a', dest: /tmp/a }":                                       "no sha256 checksum",
		"unarchive: { src: a.tgz, dest: /opt }":                                                         "from the controller",
		"unarchive: { src: /tmp/a.tgz, dest: /opt, remote_src: yes }":                                   "no creates guard",
		"user: { name: app, groups: [web], append: yes }":                                               "appends to the user's groups",
		"user: { name: app, create_home: no }":                                                          "create_home: no",
		"sysctl: { name: vm.swappiness, value: '10', sysctl_file: /etc/sysctl.d/x.conf }":               "named sysctl_file",
		"cron: { name: x, job: /bin/true, cron_file: x }":                                               "named cron_file",
		"parted: { device: /dev/sdb, number: 1, state: present }":                                       "sets no part_start",
		"parted: { device: /dev/sdb, number: 1, state: present, part_start: '0%' }":                     "must be a size in MiB, GiB or TiB",
		"parted: { device: /dev/sdb, number: 1 }":                                                       "has state info",
		"parted: { device: /dev/sdb, number: 1, state: absent }":                                        "has state absent",
		"parted: { device: /dev/sdb, number: 5, state: present, part_start: 1MiB, part_type: logical }": "logical partition",
		"parted: { device: /dev/sdb, number: 1, state: present, part_start: 1MiB, fs_type: ext4 }":      "sets fs_type",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, reason)
		}
	}
}

// Tasks the converter can't place in a circuit stay for review.
func TestConvertTaskRefusals(t *testing.T) {
	for task, reason := range map[string]string{
		"- name: as root\n      become: yes\n      file: { path: /srv, state: directory }": "sets become differently from its play",
		"- name: nothing\n      tags: [a]":                                                 "has no module the converter recognises",
		"- block:\n        - copy: { dest: /etc/a, content: x }\n      rescue:\n        - name: restart\n          command: /bin/true\n          args: { creates: /x }\n          notify: restart app": "notifies a handler from a block's rescue",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    "+task+"\n  handlers:\n    - name: restart app\n      service: { name: app, state: restarted }\n")
		found := false
		for _, r := range res.Review {
			found = found || strings.Contains(r.Reason, reason)
		}
		if !found {
			t.Errorf("%s: review %+v, want %q", task, res.Review, reason)
		}
	}
}
