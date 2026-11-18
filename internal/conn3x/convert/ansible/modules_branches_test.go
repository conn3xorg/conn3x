// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// More of each module's arguments: what converts says what it maps to.
func TestConvertModuleOptions(t *testing.T) {
	for task, want := range map[string][]string{
		"copy: { dest: /etc/sudoers.d/a, content: x, validate: 'visudo -cf \"%s\"' }":                                              {`validate = "visudo -cf %s"`},
		"lineinfile: { path: /etc/a, line: x, state: absent, create: yes }":                                                        {"line {", `state  = "absent"`, "create = true"},
		"lineinfile: { path: /etc/a, line: x, insertbefore: BOF }":                                                                 {`insert_before = "BOF"`},
		"package: { name: [a, b], state: removed }":                                                                                {`name  = "a"`, `name  = "b"`, `state = "absent"`},
		"apt: { name: nginx, state: installed, update_cache: yes }":                                                                {`name = "nginx"`, "update_cache dropped"},
		"service: { name: nginx, enabled: yes, daemon_reload: yes }":                                                               {"enabled = true", "daemon_reload dropped"},
		"user: { name: app, groups: [] }":                                                                                          {"user {", `name = "app"`},
		"group: { name: app }":                                                                                                     {"group {", `name = "app"`},
		"cron: { name: 'nightly job', special_time: daily, job: /bin/true, user: app }":                                            {`schedule = "@daily"`, `name     = "nightly-job"`, `user     = "app"`},
		"lineinfile: { path: /etc/a, regexp: '^(#?)Port', line: '\\1Port 2222', backrefs: yes }":                                   {`line     = "$${1}Port 2222"`, "backrefs = true"},
		"cron: { name: x, minute: '5', hour: '1', job: /bin/true }":                                                                {`schedule = "5 1 * * *"`},
		"postgresql_user: { name: app, db: app, priv: 'ALL' }":                                                                     {"database_grants", `"CONNECT", "CREATE", "TEMPORARY"`},
		"postgresql_user: { name: app, db: app, priv: 'TEMP,CREATE,,CONNECT' }":                                                    {`"TEMPORARY", "CREATE", "CONNECT"`},
		"postgresql_user: { name: app, role_attr_flags: 'LOGIN' }":                                                                 {"login = true"},
		"postgresql_user: { name: app, role_attr_flags: 'NOLOGIN,NOSUPERUSER,NOCREATEDB,NOCREATEROLE,NOREPLICATION,NOBYPASSRLS' }": {"login      = false", "attributes = []"},
		"postgresql_user: { name: app, password: s3cret }":                                                                         {"password_wo from an ephemeral variable"},
		"mysql_user: { name: app, priv: { 'app.*': 'SELECT,INSERT' } }":                                                            {"grants", `"SELECT", "INSERT"`},
		"mysql_user: { name: app, priv: '*.*:USAGE' }":                                                                             {"grants = {}"},
		"mysql_user: { name: app, priv: 'app.*:ALL', password: x }":                                                                {`"ALL PRIVILEGES"`, "password_wo"},
		"ufw: { rule: allow, port: '22' }":                                                                                         {`port   = "22"`},
		"lvol: { vg: data, lv: app, size: 10g, force: yes, shrink: no }":                                                           {"lvm_logical_volume {", `size = "10g"`},
		"lvol: { vg: data, lv: app, size: 10g, force: yes }":                                                                       {"force = true", "TODO(convert): force = true lets this step shrink"},
		"lvol: { vg: data, lv: app, size: 10g, resizefs: yes }":                                                                    {"TODO(convert): resizefs grew the file system"},
		"filesystem: { dev: /dev/sdb1, fstype: xfs, opts: '-L data', resizefs: yes, force: yes }": {
			`opts   = ["-L", "data"]`, "resize = true", "force  = true", "TODO(convert): force = true lets this step make"},
		"wait_for: { port: 22, timeout: 30 }":                      {"wait_for {", `timeout = "30s"`, "port    = 22"},
		"wait_for: { path: /tmp/ready, host: localhost }":          {`path = "/tmp/ready"`},
		"yum_versionlock: { name: [httpd, nginx], state: absent }": {`name  = "httpd"`, `state = "released"`},
		"dpkg_selections: { name: nginx, selection: install }":     {"package_hold {", `state = "released"`},
		"selinux: { state: enforcing, policy: targeted }":          {"selinux_mode {", "policy dropped"},
		"acl: { path: /srv, etype: user, entity: app, permissions: r-x, default: yes, state: absent }": {
			`permissions = "rx"`, "default     = true", `state       = "absent"`},
		"debconf: { name: tzdata, question: tz, vtype: boolean, value: 'yes' }":                      {`value    = "true"`},
		"debconf: { name: app, question: pw, vtype: password, value: secret }":                       {"value_wo from an ephemeral variable"},
		"alternatives: { name: java, path: /usr/bin/java11, link: /usr/bin/java, priority: 10 }":     {`link     = "/usr/bin/java"`, "priority = 10"},
		"snap: { name: [a, b], state: absent, channel: edge, classic: yes }":                         {`channel = "edge"`, "classic = true", `state   = "absent"`},
		"flatpak: { name: org.gnome.Calculator, remote: flathub, method: user, state: latest }":      {`remote = "flathub"`, `method = "user"`, `state  = "latest"`},
		"sudoers: { name: ops, group: ops, commands: ALL, runas: root, host: web1, nopassword: no }": {`group    = "ops"`, `runas    = "root"`, `host     = "web1"`},
		"docker_container: { name: web, image: nginx, command: [nginx, -g], env: { A: b }, restart_policy: always, ports: ['80:80'] }": {
			`command = ["nginx", "-g"]`, `env = {`, `restart = "always"`, `ports   = ["80:80"]`},
		"podman_container: { name: web, image: nginx, command: 'nginx -g x' }":     {`command = ["nginx", "-g", "x"]`},
		"modprobe: { name: br_netfilter, params: 'a=1 b=2', persistent: present }": {`params = ["a=1", "b=2"]`},
		"modprobe: { name: br_netfilter, state: absent, persistent: absent }":      {`state = "absent"`},
		"shell: 'cd x && make'\n      args: { chdir: /src, creates: /src/out }":    {`command = "cd '/src' && cd x && make"`, `creates = "/src/out"`},
		"command: /bin/true\n      args: { removes: /tmp/x }":                      {`removes = "/tmp/x"`},
		"file: { path: /srv, state: directory, mode: '0755' }":                     {"directory {", `mode = "0755"`},
		"file: { path: /srv/l, src: /srv/t, state: link }":                         {"link {", `target = "/srv/t"`},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		hcl := string(res.HCL)
		notes := ""
		for _, n := range res.Notes {
			notes += n.Reason + "\n"
		}
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
			continue
		}
		for _, w := range want {
			if !strings.Contains(hcl, w) && !strings.Contains(notes, w) {
				t.Errorf("%s: missing %q:\n%s", task, w, hcl)
			}
		}
	}
}

// What the converter can't prove for a module stays for review, with why.
func TestConvertModuleOptionRefusals(t *testing.T) {
	for task, reason := range map[string]string{
		"copy: { src: /etc/hosts, dest: /tmp/h, remote_src: yes }":                        "copies a file already on the host",
		"copy: { dest: /tmp/h }":                                                          "has neither content nor src",
		"copy: { dest: /tmp/h, content: x, force: no }":                                   "sets force: no",
		"copy: { dest: /tmp/h, content: x, validate: 'check' }":                           "validate has no %s",
		"copy: { dest: /tmp/h, content: x, validate: 'check %s | grep ok' }":              "validate uses shell syntax",
		"lineinfile: { path: /etc/a, line: '\\2', regexp: '^(a)', backrefs: yes }":        "naming group 2",
		"lineinfile: { path: /etc/a, line: '\\1', regexp: '^(\\s)', backrefs: yes }":      "using \\s",
		"package: { state: present }":                                                     "names no package",
		"file: { path: /srv/l, src: /srv/t, state: link, owner: root }":                   "sets owner, group or mode on a link",
		"file: { path: /srv, state: directory, recurse: yes, mode: '0755' }":              "sets recurse with a numeric mode",
		"file: { path: /srv/a, state: touch }":                                            "changes an existing file's attributes",
		"postgresql_db: { name: app, state: absent }":                                     `has state "absent"`,
		"postgresql_db: { name: app, template: template0 }":                               "sets template, which postgresql_database doesn't offer",
		"postgresql_db: { name: app, login_host: db1 }":                                   "sets login_host",
		"postgresql_user: { name: app, state: absent }":                                   `has state "absent"; postgresql_role`,
		"postgresql_user: { name: app, encrypted: no }":                                   "stores the password unencrypted",
		"postgresql_user: { name: app, no_password_changes: yes }":                        "sets no_password_changes",
		"postgresql_user: { name: app, expires: infinity }":                               "sets expires",
		"postgresql_user: { name: app, priv: CONNECT }":                                   "sets priv without db",
		"postgresql_user: { name: app, db: app, priv: 'mytable:SELECT' }":                 "on a single table",
		"postgresql_user: { name: app, db: app, priv: 'USAGE' }":                          "grants USAGE with priv",
		"postgresql_user: { name: app, db: app, priv: ',' }":                              "sets an empty priv",
		"postgresql_user: { name: app, role_attr_flags: 'CREATEDB' }":                     "names only some of SUPERUSER",
		"postgresql_user: { name: app, role_attr_flags: 'INHERIT' }":                      "sets the role flag INHERIT",
		"postgresql_privs: { db: app, roles: web, privs: SELECT, grant_option: yes }":     "sets grant_option",
		"postgresql_privs: { db: app, roles: web, privs: SELECT }":                        "grants privileges in a task of its own",
		"mysql_db: { name: app, state: dump }":                                            `has state "dump"`,
		"mysql_db: { name: app, login_user: root }":                                       "sets login_user, which mysql_database",
		"mysql_user: { name: app, state: absent }":                                        `has state "absent"; mysql_user`,
		"mysql_user: { name: app, append_privs: yes }":                                    "sets append_privs",
		"mysql_user: { name: app, encrypted: yes }":                                       "gives the password already hashed",
		"mysql_user: { name: app, update_password: on_create }":                           `has update_password "on_create"`,
		"mysql_user: { name: app, plugin: x }":                                            "sets plugin, which mysql_user",
		"mysql_user: { name: root }":                                                      "manages root, an account the server itself needs",
		"mysql_user: { name: app, priv: 'app.*' }":                                        "with no privileges after a colon",
		"mysql_user: { name: app, priv: [a] }":                                            "has a priv that isn't a string or a map",
		"mysql_user: { name: app, priv: 'app.t:SELECT' }":                                 "grants on app.t",
		"mysql_user: { name: app, priv: 'app.*:SELECT/app.*:INSERT' }":                    "grants on app.* twice",
		"mysql_user: { name: app, priv: 'app.*:FLY' }":                                    "grants FLY on app.*",
		"mysql_user: { name: app, priv: 'app.*:ALL,SELECT' }":                             "grants ALL with others",
		"firewalld: { service: http, permanent: yes }":                                    "doesn't set both permanent and immediate",
		"ansible.posix.synchronize: { src: files/site }":                                  "needs src and dest",
		"ansible.posix.synchronize: { src: a, dest: /b, mode: pull }":                     "pulls from the host",
		"ansible.posix.synchronize: { src: a, dest: /b, rsync_opts: [-z] }":               "passes rsync options",
		"ansible.posix.synchronize: { src: a, dest: /b, copy_links: yes }":                "sets dirs or copy_links",
		"ansible.posix.synchronize: { src: a, dest: /b, exclude: '*.tmp' }":               "filters what it copies",
		"ansible.posix.synchronize: { src: a, dest: b }":                                  "has a relative dest",
		"ansible.posix.synchronize: { src: nowhere, dest: /b }":                           "copies nowhere, which isn't in the playbook's",
		"lvol: { vg: data, lv: app, size: +10g }":                                         "sets a size relative to the volume's current one, +10g",
		"lvol: { vg: data, lv: '', size: 10g }":                                           "must be an LVM name",
		"filesystem: { dev: '', fstype: xfs }":                                            "must be a device path under /dev",
		"lvg: { vg: '', pvs: /dev/sdb }":                                                  "must be an LVM name",
		"wait_for: { host: db1, port: 5432 }":                                             "waits for another host",
		"wait_for: { port: 22, timeout: soon }":                                           "has a timeout that isn't a number of seconds",
		"reboot: { reboot_timeout: 600 }":                                                 "reboots on every play",
		"yum_versionlock: { name: 'httpd-0:2.4*' }":                                       "has a version or wildcard",
		"yum_versionlock: { name: 'bad name' }":                                           "package name \"bad name\" is not valid",
		"yum_versionlock: { state: present }":                                             "names no package",
		"dpkg_selections: { name: nginx, selection: purge }":                              `selection "purge" marks the package for removal`,
		"modprobe: { name: br_netfilter, persistent: absent }":                            "sets persistent: absent with state: present",
		"modprobe: { name: 'bad name' }":                                                  "must be a kernel module name",
		"acl: { path: /srv, entry: 'user:app:r' }":                                        "sets entry, the old one-string form",
		"acl: { path: /srv, etype: user, entity: app, permissions: r, recursive: yes }":   "sets recursive",
		"acl: { path: /srv, etype: user, entity: app, permissions: rwz, state: present }": "sets permissions rwz",
		"debconf: { name: tzdata }":                                                       "only names a package",
		"debconf: { name: tzdata, question: tz, vtype: string, value: x, unseen: yes }":   "sets unseen",
		"debconf: { name: tzdata, question: tz, vtype: seen }":                            "has vtype seen",
		"selinux: { state: enforcing, configfile: /etc/other }":                           "uses the config file /etc/other",
		"selinux: { state: enforcing, update_kernel_param: yes }":                         "sets update_kernel_param",
		"alternatives: { name: java, path: /usr/bin/java, subcommands: [] }":              "sets subcommands",
		"snap: { name: a, dangerous: yes }":                                               "sets dangerous",
		"snap: { channel: edge }":                                                         "names no snap",
		"flatpak: { name: org.a.B, executable: /opt/flatpak }":                            `runs "/opt/flatpak"`,
		"flatpak: { name: org.a.B, no_dependencies: yes }":                                "sets no_dependencies",
		"flatpak: { state: present }":                                                     "names no app",
		"flatpak: { name: 'https://example.com/a.flatpakref' }":                           "a ref or URL",
		"sudoers: { name: ops, user: ops, commands: ALL, sudoers_path: /etc/sudoers }":    "writes to /etc/sudoers; the sudoers step",
		"sudoers: { name: ops, user: ops, commands: ALL, setenv: yes }":                   "sets setenv",
		"sudoers: { name: ops, commands: ALL }":                                           "set one of user and group",
		"docker_container: { name: web, image: nginx, command: 'sh -c \"x\"' }":           "sets command as one string with quotes",
		"docker_container: { name: web, image: nginx, env: { A: [b] } }":                  "sets env A to something other than one value",
		"docker_container: { name: '', image: nginx }":                                    "must start with a letter or digit",
		"command: 'make creates=/x'":                                                      "sets creates inside the command line",
		"command: { chdir: /x }":                                                          "has no command",
		"command: 'ls | wc'\n      args: { creates: /x }":                                 "uses characters a shell reads",
		"command: make\n      args: { creates: '/out/*.o' }":                              "creates is a glob pattern",
		"uri: { url: 'http://x' }":                                                        "makes a request; only a uri task that retries",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, reason)
		}
	}
}
