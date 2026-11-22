// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

const netPlay = "- hosts: switches\n  gather_facts: false\n  connection: ansible.netcommon.network_cli\n  tasks:\n"

// The four *_config modules become their Conn3x steps, and a play of only
// network tasks takes network_cli without a TODO (#1169).
func TestConvertNetworkConfig(t *testing.T) {
	for task, want := range map[string][]string{
		"cisco.ios.ios_config: {lines: ['ntp server 192.0.2.10']}":                                       {"ios_config {", `lines = ["ntp server 192.0.2.10"]`},
		"cisco.ios.ios_config: {parents: ['interface GigabitEthernet1'], lines: ['description uplink']}": {`parents = ["interface GigabitEthernet1"]`, `lines   = ["description uplink"]`},
		"arista.eos.eos_config: {commands: ['ntp server 192.0.2.10']}":                                   {"eos_config {", `lines = ["ntp server 192.0.2.10"]`},
		"junipernetworks.junos.junos_config: {lines: ['set system ntp server 192.0.2.10']}":              {"junos_config {"},
		"vyos.vyos.vyos_config: {lines: ['set system ntp server 192.0.2.10'], match: line}":              {"vyos_config {"},
		"cisco.ios.ios_config: {lines: ['ntp server 192.0.2.10'], save_when: modified}":                  {"save_when dropped: Conn3x saves"},
		"arista.eos.eos_config: {lines: ['ntp server 192.0.2.10'], backup: true}":                        {"backup dropped: set device_backup_dir"},
		"junipernetworks.junos.junos_config: {lines: ['set system ntp server 192.0.2.10'], confirm: 5}":  {"confirm dropped: every change goes in under a revert timer"},
		"vyos.vyos.vyos_config: {lines: ['set system ntp server 192.0.2.10'], save: true}":               {"save dropped:"},
	} {
		res := convertString(t, netPlay+"    - "+task+"\n")
		hcl := string(res.HCL)
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v\n%s", task, res.Converted, res.Review, hcl)
			continue
		}
		for _, w := range want {
			if !strings.Contains(hcl, w) {
				t.Errorf("%s: missing %q:\n%s", task, w, hcl)
			}
		}
	}
}

// Anything that changes what's compared stays for review.
func TestConvertNetworkConfigRefusals(t *testing.T) {
	for task, reason := range map[string]string{
		"cisco.ios.ios_config: {parents: ['interface Loopback1'], lines: ['description why?']}":              "refuses ?",
		"cisco.ios.ios_config: {src: running.cfg}":                                                           "sets src",
		"cisco.ios.ios_config: {lines: ['ntp server 192.0.2.10'], match: exact}":                             "sets match: exact",
		"arista.eos.eos_config: {parents: ['interface Ethernet1'], lines: ['shutdown'], replace: block}":     "sets replace: block",
		"cisco.ios.ios_config: {lines: [{command: 'reload', prompt: 'confirm', answer: 'y'}]}":               "prompt and answer",
		"junipernetworks.junos.junos_config: {lines: ['delete system ntp']}":                                 `has the line "delete system ntp"`,
		"vyos.vyos.vyos_config: {lines: ['delete system ntp']}":                                              "takes only set lines",
		"junipernetworks.junos.junos_config: {lines: ['set system ntp server 192.0.2.10'], update: replace}": "sets update: replace",
	} {
		res := convertString(t, netPlay+"    - "+task+"\n")
		if res.Converted != 0 || !strings.Contains(reasons(res), reason) {
			t.Errorf("%s: converted %d, review %q, want %q", task, res.Converted, reasons(res), reason)
		}
	}
}

func TestConvertNetworkPlay(t *testing.T) {
	// become with enable is Arista's, and maps to the ssh block's become.
	res := convertString(t, "- hosts: switches\n  connection: network_cli\n  become: true\n  become_method: enable\n  tasks:\n    - arista.eos.eos_config: {lines: ['ntp server 192.0.2.10']}\n")
	if hcl := string(res.HCL); len(res.Review) != 0 || !strings.Contains(hcl, "become") {
		t.Errorf("EOS with enable: review %+v\n%s", res.Review, hcl)
	}
	// IOS, Junos and VyOS refuse become: the login has to start privileged.
	res = convertString(t, "- hosts: routers\n  connection: network_cli\n  become: true\n  become_method: enable\n  tasks:\n    - cisco.ios.ios_config: {lines: ['ntp server 192.0.2.10']}\n")
	if hcl := string(res.HCL); !strings.Contains(reasons(res), "only an Arista EOS ssh block takes") || strings.Contains(hcl, "become ") {
		t.Errorf("IOS with become: review %q\n%s", reasons(res), hcl)
	}
	// A play that mixes in a Linux task keeps a TODO: one ssh block can't
	// suit both.
	res = convertString(t, netPlay+"    - cisco.ios.ios_config: {lines: ['ntp server 192.0.2.10']}\n    - ansible.builtin.copy: {dest: /tmp/a, content: x}\n")
	if !strings.Contains(reasons(res), "split the network tasks into a play of their own") {
		t.Errorf("mixed play: review %q", reasons(res))
	}
	// connection: local and the rest still get the usual TODO.
	res = convertString(t, "- hosts: all\n  connection: local\n  tasks:\n    - cisco.ios.ios_config: {lines: ['ntp server 192.0.2.10']}\n")
	if !strings.Contains(reasons(res), "sets connection") {
		t.Errorf("connection: local: review %q", reasons(res))
	}
}
