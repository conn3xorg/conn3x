// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertPostgresqlSetting(t *testing.T) {
	for task, want := range map[string][]string{
		"community.postgresql.postgresql_alter_system: {param: shared_buffers, value: 256MB}": {
			"postgresql_setting {", `name  = "shared_buffers"`, `value = "256MB"`,
		},
		// postgresql_set was removed in favour of postgresql_alter_system,
		// and took name rather than param.
		"community.postgresql.postgresql_set: {name: work_mem, value: 64MB}": {`name  = "work_mem"`, `value = "64MB"`},
		"postgresql_alter_system: {param: max_connections, value: 200, login_db: app}\n      become_user: postgres": {
			`name  = "max_connections"`, `value = "200"`,
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
		"community.postgresql.postgresql_alter_system: {param: work_mem, value: _RESET}":          "resets the setting",
		"community.postgresql.postgresql_set: {name: work_mem, reset: true}":                      "sets reset",
		"community.postgresql.postgresql_alter_system: {param: work_mem, value: 1MB, port: 5433}": "sets port",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}
