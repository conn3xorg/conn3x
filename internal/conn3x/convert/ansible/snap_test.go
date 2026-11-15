// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertSnap(t *testing.T) {
	for task, want := range map[string][]string{
		"community.general.snap: { name: lxd }":                         {"snap {", `name = "lxd"`},
		"snap: { name: microk8s, channel: 1.28/stable, classic: true }": {`channel = "1.28/stable"`, "classic = true"},
		"snap: { name: chromium, state: absent }":                       {`state = "absent"`},
		"snap: { name: [lxd, hello-world], state: present }":            {`name = "lxd"`, `name = "hello-world"`},
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
		"snap: { name: lxd, state: enabled }":                    "no Conn3x equivalent",
		"snap: { name: lxd, options: [lxd.daemon.group=users] }": "options",
		"snap: { name: /tmp/x.snap, dangerous: true }":           "dangerous",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: %+v", task, res.Review)
		}
	}
}
