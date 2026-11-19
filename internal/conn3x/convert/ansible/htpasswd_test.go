// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertHtpasswd(t *testing.T) {
	res := convertString(t, "- hosts: all\n  tasks:\n    - community.general.htpasswd: {path: /etc/nginx/.htpasswd, name: admin, password: secret, mode: '0640'}\n")
	hcl := string(res.HCL)
	for _, want := range []string{"htpasswd {", `path   = "/etc/nginx/.htpasswd"`, `name   = "admin"`, "create = true", `mode   = "0640"`, "password_wo from an ephemeral variable", "apr_md5_crypt"} {
		if res.Converted != 1 || !strings.Contains(hcl, want) {
			t.Errorf("want %s in:\n%s", want, hcl)
		}
	}
	if strings.Contains(hcl, "secret") {
		t.Errorf("the password reached the output:\n%s", hcl)
	}
	res = convertString(t, "- hosts: all\n  tasks:\n    - community.general.htpasswd: {dest: /x, username: u, password: p, crypt_scheme: bcrypt, create: no}\n")
	if hcl := string(res.HCL); res.Converted != 1 || strings.Contains(hcl, "create") || strings.Contains(hcl, "Apache reads bcrypt") {
		t.Errorf("bcrypt, create no:\n%s", hcl)
	}
	res = convertString(t, "- hosts: all\n  tasks:\n    - community.general.htpasswd: {path: /x, name: u, state: absent}\n")
	if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, `state "absent"`) {
		t.Errorf("absent: %+v", res.Review)
	}
}
