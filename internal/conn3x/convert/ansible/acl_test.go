// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertACL(t *testing.T) {
	for task, want := range map[string][]string{
		"ansible.posix.acl: { path: /srv/app, entity: deploy, etype: user, permissions: rwx, state: present }": {"acl {", `entity      = "deploy"`, `permissions = "rwx"`},
		"acl: { path: /srv/app, entity: web, etype: group, permissions: r-x, default: true, state: present }":  {`permissions = "rx"`, "default     = true"},
		"acl: { path: /srv/app, entity: deploy, etype: user, state: absent, recursive: false }":                {`state  = "absent"`},
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
	for task, reason := range map[string]string{
		"acl: { path: /srv/app, entity: deploy, etype: user, permissions: rx, state: present, recursive: true }": "owns one entry",
		"acl: { path: /srv/app, entity: deploy, etype: user, permissions: rX, state: present }":                  "takes r, w and x",
		"acl: { path: /srv/app }": "query",
		"acl: { path: /srv/app, entry: 'user:deploy:rw-', state: present }": "one-string form",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: %+v", task, res.Review)
		}
	}
}
