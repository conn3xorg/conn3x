// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertMysqlVariable(t *testing.T) {
	for task, want := range map[string][]string{
		// The issue's task, from either collection.
		"community.mysql.mysql_variables: {variable: max_connections, value: 500, mode: persist}": {
			"mysql_variable {", `name  = "max_connections"`, `value = "500"`, `mode  = "persist"`,
		},
		"ansible.mysql.mysql_variables: {variable: max_connections, value: 500}": {`name  = "max_connections"`, `value = "500"`},
		"mysql_variables: {variable: innodb_buffer_pool_size, value: 1G, mode: persist_only}": {
			`value = "1G"`, `mode  = "persist_only"`, "Ansible sends 1G to SET as a string",
		},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		for _, w := range want {
			if res.Converted != 1 || !strings.Contains(string(res.HCL), w) {
				t.Errorf("%s: converted %d, want %s in:\n%s", task, res.Converted, w, res.HCL)
			}
		}
	}
	res := convertString(t, "- hosts: all\n  tasks:\n    - community.mysql.mysql_variables: {variable: max_connections, value: 500}\n")
	if strings.Contains(string(res.HCL), "mode") {
		t.Errorf("global wrote a mode:\n%s", res.HCL)
	}
	for task, reason := range map[string]string{
		"community.mysql.mysql_variables: {variable: max_connections}":                             "only reads",
		"community.mysql.mysql_variables: {variable: max_connections, value: 5, mode: session}":    `mode "session"`,
		"community.mysql.mysql_variables: {variable: max_connections, value: 5, login_port: 3307}": "sets login_port",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}
