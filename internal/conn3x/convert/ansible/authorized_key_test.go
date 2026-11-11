// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// authorized_key with exclusive keeps only the task's keys, one per line in
// key, as Ansible does, so it converts as it is.
func TestAuthorizedKeyExclusive(t *testing.T) {
	res := convertString(t, "- hosts: all\n  tasks:\n    - authorized_key:\n        user: deploy\n        exclusive: true\n        key: |\n          ssh-ed25519 AAAA a@example.com\n          ssh-ed25519 BBBB b@example.com\n")
	if res.Converted != 1 || len(res.Review) != 0 {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
	hcl := strings.Join(strings.Fields(string(res.HCL)), " ")
	for _, want := range []string{"authorized_key {", `user = "deploy"`, "exclusive = true", `ssh-ed25519 AAAA a@example.com\nssh-ed25519 BBBB b@example.com`} {
		if !strings.Contains(hcl, want) {
			t.Errorf("output lacks %q:\n%s", want, res.HCL)
		}
	}
	if res := convertString(t, "- hosts: all\n  tasks:\n    - authorized_key: {user: deploy, key: 'ssh-ed25519 AAAA', exclusive: false}\n"); strings.Contains(string(res.HCL), "exclusive") || res.Converted != 1 {
		t.Errorf("exclusive: false: converted %d\n%s", res.Converted, res.HCL)
	}
}
