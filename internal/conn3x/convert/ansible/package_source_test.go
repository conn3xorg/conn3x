// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// apt's deb and an .rpm path in place of a name become a package step
// with source, its name read from the file name; a URL stays for review,
// with what to do instead (#1350).
func TestConvertPackageSource(t *testing.T) {
	for _, c := range []struct {
		task, review string
		want         []string
	}{
		{task: "ansible.builtin.apt: { deb: /tmp/agent_1.4.0-1_amd64.deb }",
			want: []string{`name   = "agent"`, `source = "/tmp/agent_1.4.0-1_amd64.deb"`, "TODO(convert): Check the package name: the converter read agent from the file name agent_1.4.0-1_amd64.deb"}},
		{task: "ansible.builtin.dnf: { name: /tmp/agent-1.4.0-1.el9.x86_64.rpm, state: present }",
			want: []string{`name   = "agent"`, `source = "/tmp/agent-1.4.0-1.el9.x86_64.rpm"`, "TODO(convert): Check the package name"}},
		{task: "yum: { name: /opt/dl/cinc-agent-18.4.12-1.el9.x86_64.rpm }", want: []string{`name   = "cinc-agent"`}},
		{task: "community.general.zypper: { name: /opt/dl/openvox-agent-8.9.0-1.sles15.x86_64.rpm }", want: []string{`name               = "openvox-agent"`, `source             = "/opt/dl/openvox-agent-8.9.0-1.sles15.x86_64.rpm"`}},
		{task: "ansible.builtin.apt: { deb: https://example.com/agent_1.4.0_amd64.deb }", review: "from a URL; Conn3x installs only what it can verify, so download it with a download step and its sha256"},
		{task: "ansible.builtin.dnf: { name: https://example.com/agent-1.4.0-1.el9.x86_64.rpm }", review: "from a URL; Conn3x installs only what it can verify"},
		{task: "ansible.builtin.apt: { deb: /tmp/agent.deb }", review: "whose file name isn't NAME_VERSION_ARCH.deb"},
		{task: "ansible.builtin.dnf: { name: /tmp/agent.x86_64.rpm }", review: "NAME-VERSION-RELEASE.ARCH.rpm"},
		{task: "ansible.builtin.dnf: { name: /tmp/agent-1.4.0-1.el9.x86_64.rpm, state: latest }", review: "sets state latest with a package file"},
		{task: "ansible.builtin.apt: { deb: '/tmp/my agent_1.4.0_amd64.deb' }", review: "can't be a package step"},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+c.task+"\n")
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

func TestPackageFileName(t *testing.T) {
	for base, want := range map[string]string{
		"agent_1.4.0-1_amd64.deb":             "agent",
		"node-exporter_1.8.2_arm64.deb":       "node-exporter",
		"agent_1.4.0.deb":                     "",
		"agent.deb":                           "",
		"agent-1.4.0-1.el9.x86_64.rpm":        "agent",
		"cinc-agent-18.4.12-1.el9.noarch.rpm": "cinc-agent",
		"agent-1.4.0.x86_64.rpm":              "",
		"agent.rpm":                           "",
		"agent--1.x86_64.rpm":                 "",
	} {
		if got := packageFileName(base); got != want {
			t.Errorf("packageFileName(%q) = %q, want %q", base, got, want)
		}
	}
}
