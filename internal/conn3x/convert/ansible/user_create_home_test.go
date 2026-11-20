// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// create_home: false, or its older name createhome, becomes create_home =
// false; true, Ansible's default, writes nothing.
func TestConvertUserCreateHome(t *testing.T) {
	for task, want := range map[string]bool{
		"user: {name: svc, system: true, create_home: false, shell: /usr/sbin/nologin}": true,
		"user: {name: svc, createhome: no}":                                             true,
		"user: {name: svc, create_home: yes}":                                           false,
		"user: {name: svc}":                                                             false,
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		hcl := strings.Join(strings.Fields(string(res.HCL)), " ")
		if res.Converted != 1 || len(res.Review) != 0 || strings.Contains(hcl, "create_home = false") != want || strings.Contains(hcl, "create_home = true") {
			t.Errorf("%s: converted %d, review %+v:\n%s", task, res.Converted, res.Review, res.HCL)
		}
	}
}

func TestConvertUserComment(t *testing.T) {
	res := convertString(t, "- hosts: all\n  tasks:\n    - user: {name: deploy, comment: Deploy user, shell: /bin/bash}\n")
	if hcl := strings.Join(strings.Fields(string(res.HCL)), " "); res.Converted != 1 || len(res.Review) != 0 || !strings.Contains(hcl, `comment = "Deploy user"`) {
		t.Errorf("converted %d, review %+v:\n%s", res.Converted, res.Review, res.HCL)
	}
}
