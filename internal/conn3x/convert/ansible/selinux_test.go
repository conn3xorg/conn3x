// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertSELinuxMode(t *testing.T) {
	for task, want := range map[string][]string{
		"ansible.posix.selinux: { state: enforcing }":                    {"selinux_mode {", `mode = "enforcing"`},
		"ansible.posix.selinux: { state: permissive, policy: targeted }": {`mode = "permissive"`, "policy dropped"},
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
	}
	for task, reason := range map[string]string{
		"selinux: { state: disabled }": "no Conn3x equivalent",
		"selinux: { state: enforcing, policy: targeted, update_kernel_param: true }": "boot parameters",
		"selinux: { state: enforcing, configfile: /etc/selinux/alt }":                "config file",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: %+v", task, res.Review)
		}
	}
}
