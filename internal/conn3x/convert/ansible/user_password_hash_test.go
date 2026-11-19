// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// A user task's password is a hash: the step converts with a TODO to set
// password_hash_wo, and the hash isn't in the output.
func TestConvertUserPasswordHash(t *testing.T) {
	res := convertString(t, "- hosts: all\n  tasks:\n    - user: {name: app, password: '$6$salt$secrethash', update_password: on_create}\n")
	hcl := string(res.HCL)
	if res.Converted != 1 || !strings.Contains(hcl, "password_hash_wo") || !strings.Contains(hcl, "password_on_create = true") {
		t.Errorf("converted %d:\n%s", res.Converted, hcl)
	}
	if strings.Contains(hcl, "secrethash") {
		t.Errorf("the hash reached the output:\n%s", hcl)
	}
}
