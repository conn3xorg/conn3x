// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertSudoers(t *testing.T) {
	res := convertString(t, `- hosts: all
  tasks:
    - name: deploy may restart the app
      community.general.sudoers:
        name: deploy
        group: deploy
        commands: /usr/bin/systemctl restart app
`)
	hcl := string(res.HCL)
	for _, want := range []string{"sudoers {", `group      = "deploy"`, `commands   = ["/usr/bin/systemctl restart app"]`, "nopassword = true"} {
		if !strings.Contains(hcl, want) {
			t.Errorf("missing %s:\n%s", want, hcl)
		}
	}
	if res.Converted != 1 || len(res.Review) != 0 {
		t.Errorf("converted %d, review %v", res.Converted, res.Review)
	}
	res = convertString(t, "- hosts: all\n  tasks:\n    - sudoers: { name: d, user: d, commands: ALL, nopassword: false }\n")
	if strings.Contains(string(res.HCL), "nopassword") {
		t.Errorf("nopassword: false should leave the step's default:\n%s", res.HCL)
	}
	for task, want := range map[string]string{
		"sudoers: { name: d.conf, user: d, commands: ALL }":           "holds a dot",
		"sudoers: { name: d, user: d, commands: ALL, setenv: true }":  "sets setenv",
		"sudoers: { name: d, user: d, commands: ALL, state: absent }": `state "absent"`,
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, want) {
			t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, want)
		}
	}
}
