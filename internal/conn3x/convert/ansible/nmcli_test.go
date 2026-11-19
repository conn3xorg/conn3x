// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertNmcli(t *testing.T) {
	for task, want := range map[string][]string{
		"community.general.nmcli: { conn_name: eth1, ifname: eth1, type: ethernet, ip4: 10.0.0.2/24, gw4: 10.0.0.1, dns4: [10.0.0.53], state: present }": {
			`type   = "ethernet"`, `ip4    = ["10.0.0.2/24"]`, `gw4    = "10.0.0.1"`, `dns4   = ["10.0.0.53"]`, "writes the whole profile"},
		"nmcli: { conn_name: eth1, type: ethernet, method4: auto, state: present }":                                {`ifname = "eth1"`, `ip4    = ["auto"]`},
		"nmcli: { conn_name: bond0, type: bond, mode: active-backup, state: present }":                             {`bond_mode = "active-backup"`},
		"nmcli: { conn_name: bond0-p1, ifname: eth2, type: bond-slave, master: bond0, state: present }":            {`type       = "ethernet"`, `controller = "bond0"`},
		"nmcli: { conn_name: p2, ifname: eth3, type: ethernet, master: bond0, slave_type: bond, state: present }":  {`controller = "bond0"`},
		"nmcli: { conn_name: vlan10, type: vlan, vlanid: 10, vlandev: eth1, ip4: [10.10.0.2/24], state: present }": {"vlan_id     = 10", `vlan_parent = "eth1"`},
		"nmcli: { conn_name: e, type: ethernet, dns4_search: [a.test], dns6_search: [a.test], state: present }":    {`dns_search = ["a.test"]`},
		"nmcli: { conn_name: e, type: ethernet, ip6: ['2001:db8::2/64'], method4: disabled, state: present }":      {`ip4    = ["disabled"]`, `ip6    = ["2001:db8::2/64"]`},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		hcl := string(res.HCL)
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
			continue
		}
		for _, w := range want {
			if !strings.Contains(hcl, w) {
				t.Errorf("%s: missing %q:\n%s", task, w, hcl)
			}
		}
	}
	for task, reason := range map[string]string{
		"nmcli: { conn_name: e, type: ethernet, ip4: 10.0.0.2/24, routes4: ['10.4.0.0/16 10.0.0.1'], state: present }": "sets routes4",
		"nmcli: { conn_name: e, type: ethernet, state: absent }":                                                       "has state absent",
		"nmcli: { conn_name: w, type: wifi, state: present }":                                                          "makes a wifi connection",
		"nmcli: { conn_name: p, type: ethernet, master: br0, slave_type: bridge, state: present }":                     "port of a bridge",
		"nmcli: { conn_name: p, type: bond-slave, master: bond0, ip4: 10.0.0.2/24, state: present }":                   "on a bond port",
		"nmcli: { conn_name: e, type: ethernet, ip4: 10.0.0.2/24, method4: auto, state: present }":                     "with method4: auto",
		"nmcli: { conn_name: e, type: ethernet, method4: link-local, state: present }":                                 "method4: link-local",
		"nmcli: { conn_name: e, type: ethernet, dns4_search: [a.test], dns6_search: [b.test], state: present }":        "differently",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, reason)
		}
	}
}
