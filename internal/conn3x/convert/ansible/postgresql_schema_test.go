// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertPostgresqlSchema(t *testing.T) {
	for task, want := range map[string][]string{
		"community.postgresql.postgresql_schema: {db: app, name: reporting, owner: app}": {
			"postgresql_schema {", `name     = "reporting"`, `database = "app"`, `owner    = "app"`,
		},
		// Ansible's login_db defaults to postgres, so that's where it's made.
		"community.postgresql.postgresql_schema: {name: reporting}": {`name     = "reporting"`, `database = "postgres"`},
		"postgresql_schema: {schema: acme, login_db: app, cascade_drop: false}\n      become_user: postgres": {
			`name     = "acme"`, `database = "app"`,
		},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		for _, w := range want {
			if res.Converted != 1 || !strings.Contains(string(res.HCL), w) {
				t.Errorf("%s: converted %d, want %s in:\n%s", task, res.Converted, w, res.HCL)
			}
		}
	}
	for task, reason := range map[string]string{
		"community.postgresql.postgresql_schema: {name: r, db: d, state: absent}":          `state "absent"`,
		"community.postgresql.postgresql_schema: {name: r, db: d, cascade_drop: true}":     "cascade_drop",
		"community.postgresql.postgresql_schema: {name: r, db: d, comment: 'for reports'}": "sets comment",
		"community.postgresql.postgresql_schema: {name: r, db: d, login_host: db.example}": "sets login_host",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}
