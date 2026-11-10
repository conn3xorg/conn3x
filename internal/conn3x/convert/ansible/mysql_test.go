// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestMySQLMappings(t *testing.T) {
	for task, wants := range map[string][]string{
		`community.mysql.mysql_db: {name: shop, encoding: utf8mb4, collation: utf8mb4_unicode_ci}`: {"mysql_database {", `name      = "shop"`, `charset   = "utf8mb4"`, `collation = "utf8mb4_unicode_ci"`},
		`mysql_db: {name: shop, state: present}`:                                                   {"mysql_database {", `name = "shop"`},
		`community.mysql.mysql_user: {name: shop, host: '10.0.0.%', password: '{{ pw }}', priv: 'shop.*:ALL'}`: {
			"mysql_user {", `name = "shop"`, `host = "10.0.0.%"`, `shop = ["ALL PRIVILEGES"]`, "TODO(convert): Set password_wo", "global and table privileges",
		},
		`mysql_user: {name: ro, priv: '*.*:USAGE/shop.*:SELECT,SHOW VIEW/logs.*:select'}`: {`logs = ["SELECT"]`, `shop = ["SELECT", "SHOW VIEW"]`},
		`mysql_user: {name: app, priv: {'app.*': 'SELECT,INSERT'}}`:                       {`app = ["SELECT", "INSERT"]`},
		`mysql_user: {name: app}`: {"mysql_user {", `name = "app"`},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
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

func TestMySQLLeftForAPerson(t *testing.T) {
	for reason, task := range map[string]string{
		`has state "absent"`:          `mysql_db: {name: shop, state: absent}`,
		`has state "import"`:          `mysql_db: {name: shop, state: import, target: /tmp/x.sql}`,
		"sets login_host":             `mysql_db: {name: shop, login_host: db.example.com}`,
		"not a single value":          `mysql_db: {name: [a, b]}`,
		"append_privs":                `mysql_user: {name: a, priv: 'shop.*:SELECT', append_privs: true}`,
		"already hashed":              `mysql_user: {name: a, password: '*ABC', encrypted: true}`,
		`update_password "on_create"`: `mysql_user: {name: a, password: x, update_password: on_create}`,
		"grants on shop.orders":       `mysql_user: {name: a, priv: 'shop.orders:SELECT'}`,
		"grants on *.*":               `mysql_user: {name: a, priv: '*.*:RELOAD'}`,
		"grants GRANT on":             `mysql_user: {name: a, priv: 'shop.*:ALL,GRANT'}`,
		"ALL with others":             `mysql_user: {name: a, priv: 'shop.*:ALL,SELECT'}`,
		"the server itself needs":     `mysql_user: {name: root, password: x}`,
		"sets tls_requires":           `mysql_user: {name: a, tls_requires: {SSL: null}}`,
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}

// A user's password is never copied, whether the task converts or not.
func TestMySQLPasswordNotCopied(t *testing.T) {
	const secret = "s3ntinel-my-pw"
	for _, task := range []string{
		`mysql_user: {name: a, password: ` + secret + `, priv: 'a.*:ALL'}`,
		`mysql_user: {name: a, password: ` + secret + `, update_password: on_create}`,
		`mysql_db: {name: a, login_password: ` + secret + `}`,
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if strings.Contains(string(res.HCL), secret) {
			t.Errorf("%s: the password reached the output:\n%s", task, res.HCL)
		}
	}
}
