// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// dnf's enablerepo becomes enable_repositories and apt's default_release
// target_release; disablerepo stays for review (#1351).
func TestConvertPackageRepoRelease(t *testing.T) {
	for _, c := range []struct {
		task, review string
		want         []string
	}{
		{task: "ansible.builtin.dnf: { name: nasm, enablerepo: crb, state: present }",
			want: []string{`name                = "nasm"`, `enable_repositories = ["crb"]`}},
		{task: "ansible.builtin.yum: { name: nasm, enablerepo: 'crb,epel' }", want: []string{`enable_repositories = ["crb", "epel"]`}},
		{task: "ansible.builtin.dnf5: { name: nasm, enablerepo: [crb], state: latest }", want: []string{`enable_repositories = ["crb"]`, `state               = "latest"`}},
		{task: "ansible.builtin.apt: { name: cockpit, default_release: bookworm-backports }",
			want: []string{`name           = "cockpit"`, `target_release = "bookworm-backports"`}},
		{task: "ansible.builtin.apt: { name: cockpit, default_release: '{{ rel }}-backports' }", want: []string{`target_release = "bookworm-backports"`}},
		{task: "ansible.builtin.dnf: { name: nasm, disablerepo: epel }", review: "sets disablerepo, which the converter can't translate yet"},
		{task: "ansible.builtin.dnf: { name: nasm, enablerepo: 'epel*' }", review: `repository ID "epel*" is not valid`},
		{task: "ansible.builtin.apt: { name: cockpit, default_release: 'a b' }", review: `target_release "a b" is not valid`},
		{task: "ansible.builtin.package: { name: nasm, enablerepo: crb }", review: "sets enablerepo"},
	} {
		res := convertString(t, "- hosts: all\n  vars:\n    rel: bookworm\n  tasks:\n    - "+c.task+"\n")
		hcl := string(res.HCL)
		if c.review != "" {
			if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, c.review) {
				t.Errorf("%s: converted %d, review %+v, want review %q", c.task, res.Converted, res.Review, c.review)
			}
			continue
		}
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v:\n%s", c.task, res.Converted, res.Review, hcl)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(hcl, w) {
				t.Errorf("%s: missing %q in:\n%s", c.task, w, hcl)
			}
		}
	}
}
