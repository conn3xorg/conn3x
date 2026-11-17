// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// lineinfile's and blockinfile's validate become the edit step's, as
// copy's becomes the file step's.
func TestEditValidateConverts(t *testing.T) {
	res := convertString(t, `- hosts: all
  become: true
  tasks:
    - name: Sudo
      lineinfile: {path: /etc/sudoers, line: "%ops ALL=(ALL) ALL", validate: "visudo -cf %s"}
    - name: Sshd
      blockinfile: {path: /etc/ssh/sshd_config, block: "UseDNS no", validate: "/usr/sbin/sshd -t -f %s"}
    - name: No placeholder
      lineinfile: {path: /etc/x, line: x, validate: "true"}
`)
	hcl := string(res.HCL)
	for _, want := range []string{`validate = "visudo -cf %s"`, `validate = "/usr/sbin/sshd -t -f %s"`} {
		if !strings.Contains(strings.Join(strings.Fields(hcl), " "), want) {
			t.Errorf("no %s in:\n%s", want, hcl)
		}
	}
	if res.Converted != 2 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "validate has no %s") {
		t.Errorf("converted %d, review %+v", res.Converted, res.Review)
	}
}

// lineinfile's mode, owner and group are set with the edit.
func TestEditModeConverts(t *testing.T) {
	res := convertString(t, `- hosts: all
  become: true
  tasks:
    - name: Sshd
      lineinfile: {path: /etc/ssh/sshd_config, regexp: "^UseDNS", line: "UseDNS no", mode: 0600, owner: root, group: root}
`)
	hcl := strings.Join(strings.Fields(string(res.HCL)), " ")
	if res.Converted != 1 || !strings.Contains(hcl, `mode = "0600"`) || !strings.Contains(hcl, `owner = "root"`) || !strings.Contains(hcl, `group = "root"`) {
		t.Errorf("converted %d, review %+v\n%s", res.Converted, res.Review, res.HCL)
	}
}
