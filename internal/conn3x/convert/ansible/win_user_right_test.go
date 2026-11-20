// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertWinUserRight(t *testing.T) {
	for task, want := range map[string][]string{
		`ansible.windows.win_user_right: {name: SeServiceLogonRight, users: ['.\svc_app'], action: add}`: {
			"windows_user_right {", `name       = "SeServiceLogonRight"`, `principals = [".\\svc_app"]`,
		},
		`win_user_right: {name: SeRemoteInteractiveLogonRight, users: [Administrators, 'LAB\ops']}`: {
			`principals    = ["Administrators", "LAB\\ops"]`, "authoritative = true",
		},
		`win_user_right: {name: SeDebugPrivilege, users: [], action: set}`: {`name          = "SeDebugPrivilege"`, "authoritative = true"},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		hcl := string(res.HCL)
		if res.Converted != 1 {
			t.Errorf("%s: converted %d:\n%s", task, res.Converted, hcl)
			continue
		}
		for _, w := range want {
			if !strings.Contains(hcl, w) {
				t.Errorf("%s: no %q in:\n%s", task, w, hcl)
			}
		}
		if strings.Contains(task, "action: add") && strings.Contains(hcl, "authoritative") {
			t.Errorf("%s: add made it authoritative:\n%s", task, hcl)
		}
	}
	for task, reason := range map[string]string{
		`win_user_right: {name: SeDebugPrivilege, users: [a], action: remove}`: "takes the right from users",
		`win_user_right: {name: SeDebugPrivilege, users: [], action: add}`:     "adds no users",
		`win_user_right: {users: [a]}`:                                         "has no name",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}
