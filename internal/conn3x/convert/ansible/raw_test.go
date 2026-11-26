// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// The raw task that installs Python for Ansible's modules becomes no step,
// since Conn3x runs no Python on the host; any other raw task stays for
// review, with what to write instead (#1345).
func TestConvertRaw(t *testing.T) {
	const other = "runs a command with raw, which has no creates or removes"
	for task, review := range map[string]string{
		"ansible.builtin.raw: test -e /usr/bin/python3 || (apt-get -y update && apt-get install -y python3-minimal)": "",
		"raw: test -e /usr/bin/python3 || dnf install -y python3":                                                    "",
		"raw: command -v python3 || (apk update && apk add --no-cache python3)":                                      "",
		"raw: which python || yum -y install python python-devel":                                                    "",
		"raw: apt-get install -y python3 python3-apt":                                                                "",
		"raw: zypper -n in python3":                                                                                  "",
		"raw: test -e /usr/bin/python3 || apt-get install -y python3 curl":                                           other,
		"raw: test -e /usr/bin/python3 || apt-get install -y python3; rm -rf /tmp/x":                                 other,
		"raw: test -e /usr/bin/python3 || (apt-get update && apt-get install -y python3) && reboot":                  other,
		"raw: test -e /etc/hosts || apt-get install -y python3":                                                      other,
		"raw: apt-get update": other,
		"raw: reboot":         other,
		"raw: test -e /usr/bin/python3 || apt-get install -y python3\n      args: { executable: /bin/bash }": other,
		"raw: test -e /usr/bin/python3 || apt-get install -y '{{ py }}'":                                     other,
	} {
		res := convertString(t, "- hosts: all\n  gather_facts: false\n  tasks:\n    - "+task+"\n")
		hcl := string(res.HCL)
		if review != "" {
			if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, review) {
				t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, review)
			}
			continue
		}
		// Dropped, it still counts as converted, and says so.
		if res.Converted != 1 || len(res.Review) != 0 || strings.Contains(hcl, `step "`) {
			t.Errorf("%s: converted %d, review %+v:\n%s", task, res.Converted, res.Review, hcl)
			continue
		}
		for _, w := range []string{"dropped: this installs Python for Ansible's modules", "TODO(convert): if a later step runs python, add a package step for python3."} {
			if !strings.Contains(hcl, w) {
				t.Errorf("%s: missing %q in:\n%s", task, w, hcl)
			}
		}
	}
}
