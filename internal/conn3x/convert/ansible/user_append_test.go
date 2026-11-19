// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertUserAppend(t *testing.T) {
	res := convertString(t, "- hosts: all\n  tasks:\n    - user: {name: app, groups: [docker], append: yes}\n")
	if hcl := string(res.HCL); res.Converted != 1 || !strings.Contains(hcl, "append = true") || !strings.Contains(hcl, `groups = ["docker"]`) {
		t.Errorf("converted %d:\n%s", res.Converted, hcl)
	}
	res = convertString(t, "- hosts: all\n  tasks:\n    - user: {name: app, groups: [docker]}\n")
	if strings.Contains(string(res.HCL), "append") {
		t.Errorf("append without append:\n%s", res.HCL)
	}
}
