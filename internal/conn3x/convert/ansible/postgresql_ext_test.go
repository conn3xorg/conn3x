// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertPostgresqlExt(t *testing.T) {
	for task, want := range map[string][]string{
		"community.postgresql.postgresql_ext: {name: postgis, db: gis}": {"postgresql_extension {", `name     = "postgis"`, `database = "gis"`},
		"community.postgresql.postgresql_ext: {ext: pgcrypto, login_db: app, schema: ext, version: '1.3', cascade: true}\n      become_user: postgres": {
			`schema   = "ext"`, `version  = "1.3"`, "cascade  = true",
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
		"community.postgresql.postgresql_ext: {name: x, db: d, state: absent}":          `state "absent"`,
		"community.postgresql.postgresql_ext: {name: x, db: d, version: latest}":        "version latest",
		"community.postgresql.postgresql_ext: {name: x, db: d, login_host: db.example}": "sets login_host",
		"community.postgresql.postgresql_ext: {name: x, db: d, comment: 'for the app'}": "sets comment",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}
