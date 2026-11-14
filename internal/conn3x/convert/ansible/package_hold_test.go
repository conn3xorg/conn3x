// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertPackageHolds(t *testing.T) {
	for task, want := range map[string][]string{
		"ansible.builtin.dpkg_selections: { name: python3, selection: hold }": {"package_hold {", `name = "python3"`},
		"dpkg_selections: { name: python3, selection: install }":              {`state = "released"`},
		"community.general.yum_versionlock: { name: [kernel, httpd] }":        {`name = "kernel"`, `name = "httpd"`},
		"community.general.yum_versionlock: { name: kernel, state: absent }":  {`state = "released"`},
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
		"dpkg_selections: { name: python3, selection: purge }": "marks the package for removal",
		"yum_versionlock: { name: \"httpd-0:2.4.57-2.el9\" }":  "name only",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: %+v", task, res.Review)
		}
	}
}
