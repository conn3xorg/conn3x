// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// A command or shell task's environment becomes the step's; another
// module's, or one that isn't a mapping, stays for review.
func TestConvertCommandEnvironment(t *testing.T) {
	res := convertString(t, "- hosts: all\n  vars: {prefix: /opt/app}\n  tasks:\n    - command: {cmd: make install, creates: /x}\n      environment: {PREFIX: '{{ prefix }}', PATH: /usr/bin}\n")
	hcl := string(res.HCL)
	if res.Converted != 1 || !strings.Contains(hcl, "environment = {") || !strings.Contains(hcl, `PREFIX = "/opt/app"`) {
		t.Errorf("command: converted %d:\n%s", res.Converted, hcl)
	}
	for playbook, reason := range map[string]string{
		"- hosts: all\n  tasks:\n    - package: {name: htop}\n      environment: {http_proxy: http://p:3128}\n": "uses environment",
		"- hosts: all\n  tasks:\n    - command: {cmd: x, creates: /x}\n      environment: '{{ proxy_env }}'\n":   "uses environment",
	} {
		res := convertString(t, playbook)
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("converted %d, review %+v, for:\n%s", res.Converted, res.Review, playbook)
		}
	}
}
