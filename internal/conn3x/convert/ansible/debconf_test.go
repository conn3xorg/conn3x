// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertDebconf(t *testing.T) {
	for task, want := range map[string][]string{
		"ansible.builtin.debconf: { name: postfix, question: postfix/main_mailer_type, vtype: select, value: Internet Site }": {"debconf {", `name     = "postfix"`, `question = "postfix/main_mailer_type"`, `vtype    = "select"`, `value    = "Internet Site"`},
		"debconf: { name: iptables-persistent, question: iptables-persistent/autosave_v4, vtype: boolean, value: 'yes' }":     {`vtype    = "boolean"`, `value    = "true"`},
		"debconf: { name: app, question: app/db_password, vtype: password, value: hunter2 }":                                  {`vtype    = "password"`, "Set value_wo from an ephemeral variable"},
	} {
		res := convertString(t, "- hosts: all\n  become: true\n  tasks:\n    - "+task+"\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %v", task, res.Converted, res.Review)
		}
		for _, w := range want {
			if !strings.Contains(string(res.HCL), w) {
				t.Errorf("%s: missing %s:\n%s", task, w, res.HCL)
			}
		}
		if strings.Contains(string(res.HCL), "hunter2") {
			t.Errorf("%s: the password was copied:\n%s", task, res.HCL)
		}
	}
	for task, reason := range map[string]string{
		"debconf: { name: postfix }": "only names a package",
		"debconf: { name: postfix, question: postfix/main_mailer_type, vtype: select, value: Internet Site, unseen: true }": "unseen",
		"debconf: { name: postfix, question: postfix/main_mailer_type, vtype: seen, value: 'true' }":                        "vtype seen",
	} {
		res := convertString(t, "- hosts: all\n  become: true\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: %+v", task, res.Review)
		}
	}
}
