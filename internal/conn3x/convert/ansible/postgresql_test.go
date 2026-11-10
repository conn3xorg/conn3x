// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestPostgreSQLMappings(t *testing.T) {
	for task, wants := range map[string][]string{
		`community.postgresql.postgresql_db: {name: shop, owner: shop, encoding: UTF8}`: {"postgresql_database {", `name     = "shop"`, `owner    = "shop"`, `encoding = "UTF8"`},
		`postgresql_db: {db: shop, state: present}`:                                     {"postgresql_database {", `name = "shop"`},
		`community.postgresql.postgresql_user: {name: shop, password: '{{ pw }}'}`:      {"postgresql_role {", `name = "shop"`, "TODO(convert): Set password_wo"},
		`postgresql_user: {user: ro, role_attr_flags: NOLOGIN}`:                         {"postgresql_role {", "login = false"},
		`postgresql_user: {name: admin, role_attr_flags: 'CREATEDB,CREATEROLE,NOSUPERUSER,NOREPLICATION,NOBYPASSRLS'}`: {
			`attributes = ["CREATEDB", "CREATEROLE"]`,
		},
		`postgresql_user: {name: plain, role_attr_flags: 'nosuperuser,nocreatedb,nocreaterole,noreplication,nobypassrls,login'}`: {
			"attributes = []", "login      = true",
		},
	} {
		res := convertString(t, "- hosts: all\n  become: true\n  tasks:\n    - "+task+"\n      become_user: postgres\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
			continue
		}
		for _, w := range wants {
			if !strings.Contains(string(res.HCL), w) {
				t.Errorf("%s: output lacks %q:\n%s", task, w, res.HCL)
			}
		}
	}
}

func TestPostgreSQLLeftForAPerson(t *testing.T) {
	for reason, task := range map[string]string{
		`has state "absent"`:      `postgresql_db: {name: shop, state: absent}`,
		`has state "dump"`:        `postgresql_db: {name: shop, state: dump, target: /tmp/x.sql}`,
		"sets template":           `postgresql_db: {name: shop, template: template0}`,
		"sets login_host":         `postgresql_db: {name: shop, login_host: db.example.com}`,
		"unencrypted":             `postgresql_user: {name: a, password: x, encrypted: false}`,
		"no_password_changes":     `postgresql_user: {name: a, password: x, no_password_changes: true}`,
		"sets db":                 `postgresql_user: {name: a, db: shop, priv: ALL}`,
		"names only some":         `postgresql_user: {name: a, role_attr_flags: CREATEDB}`,
		"role flag NOINHERIT":     `postgresql_user: {name: a, role_attr_flags: NOINHERIT}`,
		`has state "absent", and`: `postgresql_user: {name: a, state: absent}`,
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, strings.TrimSuffix(reason, ", and")) {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}

// A role's password is never copied, whether the task converts or not.
func TestPostgreSQLPasswordNotCopied(t *testing.T) {
	const secret = "s3ntinel-pg-pw"
	for _, task := range []string{
		`postgresql_user: {name: a, password: ` + secret + `}`,
		`postgresql_user: {name: a, password: ` + secret + `, encrypted: false}`,
		`postgresql_db: {name: a, login_password: ` + secret + `}`,
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if strings.Contains(string(res.HCL), secret) {
			t.Errorf("%s: the password reached the output:\n%s", task, res.HCL)
		}
	}
}
