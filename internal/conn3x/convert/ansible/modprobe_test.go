// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertModprobe(t *testing.T) {
	for task, want := range map[string][]string{
		"community.general.modprobe: { name: br_netfilter, persistent: present }": {`name = "br_netfilter"`},
		"modprobe: { name: dummy, params: numdummies=2 }":                         {`params     = ["numdummies=2"]`, "persistent = false"},
		"modprobe: { name: dummy, state: absent, persistent: absent }":            {`state = "absent"`},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %v", task, res.Converted, res.Review)
		}
		for _, w := range want {
			if !strings.Contains(string(res.HCL), w) {
				t.Errorf("%s: missing %s:\n%s", task, w, res.HCL)
			}
		}
	}
	res := convertString(t, "- hosts: all\n  tasks:\n    - modprobe: { name: dummy, persistent: absent }\n")
	if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "can't do in one step") {
		t.Errorf("present with persistent absent: %+v", res.Review)
	}
}
