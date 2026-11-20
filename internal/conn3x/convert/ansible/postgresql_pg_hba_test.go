// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertPostgresqlPgHba(t *testing.T) {
	const task = "community.postgresql.postgresql_pg_hba: "
	for args, want := range map[string][]string{
		// The issue's task, with become_user: postgres, which a line step
		// doesn't need since it keeps the file's owner.
		"{dest: /etc/postgresql/17/main/pg_hba.conf, contype: host, users: app, source: 10.0.0.0/24, databases: app, method: scram-sha-256}\n      become_user: postgres": {
			"line {", `path          = "/etc/postgresql/17/main/pg_hba.conf"`,
			`line          = "host app app 10.0.0.0/24 scram-sha-256"`,
			`regexp        = "^\\s*host\\s+app\\s+app\\s+10\\.0\\.0\\.0/24(\\s|$)"`,
			`insert_before = "^\\s*host(ssl|nossl|gssenc|nogssenc)?\\s+all\\s+all\\s"`,
			"Ansible sorts the whole of pg_hba.conf",
		},
		// local has no address in the line or the key, even if one is given.
		"{dest: /f, contype: local, databases: all, users: app, method: peer, address: 10.0.0.0/8}": {
			`line          = "local all app peer"`, `regexp        = "^\\s*local\\s+all\\s+app(\\s|$)"`,
			`insert_before = "^\\s*local\\s+all\\s+all\\s"`,
		},
		// Ansible's defaults: all, all, samehost, md5.
		"{dest: /f, contype: host}": {`line          = "host all all samehost md5"`},
		// An address and netmask are written as one network, as Ansible does.
		"{dest: /f, contype: hostssl, databases: app, users: app, address: 192.168.0.0, netmask: 255.255.0.0, method: scram-sha-256}": {
			`line          = "hostssl app app 192.168.0.0/16 scram-sha-256"`,
		},
		// Options are sorted by key, as Ansible writes them.
		"{dest: /f, contype: host, users: app, databases: app, address: 10.0.0.0/8, method: ldap, options: 'ldapserver=ldap.example ldapbasedn=dc=example'}": {
			`line          = "host app app 10.0.0.0/8 ldap ldapbasedn=dc=example ldapserver=ldap.example"`,
		},
		// A user name with a dot is escaped in the key.
		"{dest: /f, contype: host, databases: app, users: j.doe, address: 10.0.0.0/8}": {
			`regexp        = "^\\s*host\\s+app\\s+j\\.doe\\s+10\\.0\\.0\\.0/8(\\s|$)"`,
		},
		"{dest: /f, contype: host, databases: app, users: app, address: 'fd00::/8', state: absent}": {
			`state  = "absent"`, `regexp = "^\\s*host\\s+app\\s+app\\s+fd00::/8(\\s|$)"`,
		},
		"{dest: /f, contype: host, address: db.example, create: true}": {`"host all all db.example md5"`, `create        = true`},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+args+"\n")
		for _, w := range want {
			if res.Converted != 1 || !strings.Contains(string(res.HCL), w) {
				t.Errorf("%s: converted %d, want %s in:\n%s", args, res.Converted, w, res.HCL)
			}
		}
	}
	for args, reason := range map[string]string{
		"{dest: /f, rules: [{contype: host}]}":                               "sets rules",
		"{dest: /f, contype: host, overwrite: true}":                         "sets overwrite",
		"{dest: /f, contype: host, comment: app}":                            "sets comment",
		"{dest: /f, users: app}":                                             "has no contype",
		"{dest: /f, contype: host, users: 'app,reporter'}":                   "lists several",
		"{dest: /f, contype: host, address: 10.0.0.1/24}":                    "host bits set",
		"{dest: /f, contype: host, address: 10.0.0.1}":                       "no netmask",
		"{dest: /f, contype: host, address: 10.0.0.0, netmask: 255.0.255.0}": "isn't contiguous",
		"{dest: /f, contype: host, address: 10.0.0.0/8, netmask: 255.0.0.0}": "CIDR form",
		"{dest: /f, contype: host, method: plain}":                           "has method plain",
		"{dest: /f, contype: host, options: ldapserver}":                     "has options",
		"{dest: /f, contype: host, users: '{{ lookup(\"env\", \"U\") }}'}":   "",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+args+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v", args, res.Converted, res.Review)
		}
	}
}
