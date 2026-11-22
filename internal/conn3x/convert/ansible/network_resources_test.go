// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// Ansible's network resource modules become a Conn3x step per item (#1170).
func TestConvertNetworkResources(t *testing.T) {
	for task, want := range map[string][]string{
		"arista.eos.eos_hostname: {config: {hostname: leaf1}}":                                     {"eos_hostname {", `name = "leaf1"`},
		"junipernetworks.junos.junos_hostname: {config: {hostname: sw1}, state: replaced}":         {"junos_hostname {", `name = "sw1"`},
		"vyos.vyos.vyos_hostname: {config: {hostname: r1}}":                                        {"vyos_hostname {"},
		"arista.eos.eos_vlans: {config: [{vlan_id: 10, name: users}], state: merged}":              {"eos_vlan {", "vlan_id = 10", `name    = "users"`},
		"junipernetworks.junos.junos_vlans: {config: [{name: users, vlan_id: 10}]}":                {"junos_vlan {", `name    = "users"`, "vlan_id = 10"},
		"arista.eos.eos_interfaces: {config: [{name: Ethernet1, description: uplink, mtu: 9000}]}": {"eos_interface {", `description = "uplink"`, "mtu         = 9000"},
		// Junos and VyOS default enabled to true, so it's written out.
		"junipernetworks.junos.junos_interfaces: {config: [{name: ge-0/0/1, description: uplink}]}": {"junos_interface {", "enabled     = true"},
		"vyos.vyos.vyos_interfaces: {config: [{name: eth1, enable: false}]}":                        {"vyos_interface {", "enabled = false"},
		"vyos.vyos.vyos_l3_interfaces: {config: [{name: eth1, ipv4: [{address: 192.0.2.1/24}], ipv6: [{address: '2001:db8::1/64'}]}]}": {
			"vyos_interface {", `addresses = ["192.0.2.1/24", "2001:db8::1/64"]`},
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
	// EOS has no default for enabled, so nothing is written.
	res := convertString(t, netPlay+"    - arista.eos.eos_interfaces: {config: [{name: Ethernet1, description: x}]}\n")
	if strings.Contains(string(res.HCL), "enabled") {
		t.Errorf("an EOS interface without enabled got one:\n%s", res.HCL)
	}
}

func TestConvertNetworkResourceLists(t *testing.T) {
	res := convertString(t, netPlay+"    - name: vlans\n      arista.eos.eos_vlans: {config: [{vlan_id: 10}, {vlan_id: 20}, {vlan_id: 30}]}\n")
	hcl := string(res.HCL)
	for _, w := range []string{`step "vlans_vlan_10"`, `step "vlans_vlan_20"`, `step "vlans_vlan_30"`} {
		if !strings.Contains(hcl, w) {
			t.Errorf("missing %s:\n%s", w, hcl)
		}
	}
}

func TestConvertNetworkResourceRefusals(t *testing.T) {
	for task, reason := range map[string]string{
		"arista.eos.eos_vlans: {config: [{vlan_id: 10}], state: overridden}":                              "sets state: overridden",
		"arista.eos.eos_vlans: {state: gathered}":                                                         "sets state: gathered",
		"arista.eos.eos_hostname: {config: {hostname: leaf1}, state: deleted}":                            "sets state: deleted",
		"arista.eos.eos_vlans: {config: [{vlan_id: 10, state: suspend}]}":                                 "state to suspend",
		"junipernetworks.junos.junos_vlans: {config: [{name: users, vlan_id: 10, l3_interface: irb.10}]}": "sets l3_interface",
		"junipernetworks.junos.junos_vlans: {config: [{name: users}]}":                                    "without a vlan_id",
		"arista.eos.eos_vlans: {config: [{vlan_id: 5000}]}":                                               "without a vlan_id from 1 to 4094",
		"arista.eos.eos_interfaces: {config: [{name: Ethernet1, speed: 10g}]}":                            "sets speed",
		"vyos.vyos.vyos_l3_interfaces: {config: [{name: eth1, vifs: [{vlan_id: 10}]}]}":                   "sets vifs",
	} {
		res := convertString(t, netPlay+"    - "+task+"\n")
		if res.Converted != 0 || !strings.Contains(reasons(res), reason) {
			t.Errorf("%s: converted %d, review %q, want %q", task, res.Converted, reasons(res), reason)
		}
	}
	// A play of resource modules takes network_cli like one of *_config.
	res := convertString(t, netPlay+"    - arista.eos.eos_hostname: {config: {hostname: leaf1}}\n")
	if strings.Contains(reasons(res), "connection") {
		t.Errorf("network_cli with a resource module: %q", reasons(res))
	}
}
