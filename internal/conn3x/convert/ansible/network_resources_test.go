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
		"cisco.ios.ios_vlans: {config: [{vlan_id: 10, name: users, state: active}]}":               {"ios_vlan {", "vlan_id = 10", `name    = "users"`},
		"cisco.ios.ios_vlans: {config: [{vlan_id: 20}], state: replaced}":                          {"ios_vlan {", "vlan_id = 20"},
		"cisco.ios.ios_hostname: {config: {hostname: edge01}}":                                     {"ios_hostname {", `name = "edge01"`},
		"vyos.vyos.vyos_hostname: {config: {hostname: r1}}":                                        {"vyos_hostname {"},
		"arista.eos.eos_vlans: {config: [{vlan_id: 10, name: users}], state: merged}":              {"eos_vlan {", "vlan_id = 10", `name    = "users"`},
		"junipernetworks.junos.junos_vlans: {config: [{name: users, vlan_id: 10}]}":                {"junos_vlan {", `name    = "users"`, "vlan_id = 10"},
		"arista.eos.eos_interfaces: {config: [{name: Ethernet1, description: uplink, mtu: 9000}]}": {"eos_interface {", `description = "uplink"`, "mtu         = 9000"},
		// Junos and VyOS default enabled to true, so it's written out.
		"junipernetworks.junos.junos_interfaces: {config: [{name: ge-0/0/1, description: uplink}]}":               {"junos_interface {", "enabled     = true"},
		"cisco.ios.ios_interfaces: {config: [{name: GigabitEthernet1/0/1, description: uplink, mtu: 9000}]}":      {"ios_interface {", `description = "uplink"`, "mtu         = 9000"},
		"cisco.ios.ios_l2_interfaces: {config: [{name: GigabitEthernet1/0/5, mode: access, access: {vlan: 10}}]}": {"ios_interface {", `mode        = "access"`, "access_vlan = 10"},
		"cisco.ios.ios_l2_interfaces: {config: [{name: GigabitEthernet1/0/48, mode: trunk}]}":                     {"ios_interface {", `mode = "trunk"`},
		// replaced sets the trunk's whole list, as the step does; ranges are
		// written out, sorted and without repeats.
		"cisco.ios.ios_l2_interfaces: {config: [{name: GigabitEthernet1/0/48, mode: trunk, trunk: {allowed_vlans: ['20', '10-12', '11']}}], state: replaced}": {"ios_interface {", "allowed_vlans = [10, 11, 12, 20]"},
		"vyos.vyos.vyos_interfaces: {config: [{name: eth1, enable: false}]}":                                                                                  {"vyos_interface {", "enabled = false"},
		"vyos.vyos.vyos_l3_interfaces: {config: [{name: eth1, ipv4: [{address: 192.0.2.1/24}], ipv6: [{address: '2001:db8::1/64'}]}], state: replaced}": {
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

// A play variable is filled in before the name is checked, so a bad value
// is caught too, and a good one converts.
func TestConvertNetworkHostnameFromAVariable(t *testing.T) {
	for value, converted := range map[string]int{"leaf1": 1, "leaf_1": 0} {
		play := strings.Replace(netPlay, "  tasks:\n", "  vars: {name: "+value+"}\n  tasks:\n", 1)
		res := convertString(t, play+"    - arista.eos.eos_hostname: {config: {hostname: '{{ name }}'}}\n")
		if res.Converted != converted {
			t.Errorf("%s: converted %d, review %q:\n%s", value, res.Converted, reasons(res), res.HCL)
		}
	}
}

func TestConvertNetworkResourceLists(t *testing.T) {
	res := convertString(t, netPlay+"    - name: vlans\n      arista.eos.eos_vlans: {config: [{vlan_id: 10}, {vlan_id: 20}, {vlan_id: 30}], state: replaced}\n")
	hcl := string(res.HCL)
	for _, w := range []string{`step "vlans_vlan_10"`, `step "vlans_vlan_20"`, `step "vlans_vlan_30"`} {
		if !strings.Contains(hcl, w) {
			t.Errorf("missing %s:\n%s", w, hcl)
		}
	}
}

func TestConvertNetworkResourceRefusals(t *testing.T) {
	for task, reason := range map[string]string{
		"arista.eos.eos_vlans: {config: [{vlan_id: 10}], state: overridden}":   "sets state: overridden",
		"arista.eos.eos_vlans: {state: gathered}":                              "sets state: gathered",
		"arista.eos.eos_hostname: {config: {hostname: leaf1}, state: deleted}": "sets state: deleted",
		"cisco.ios.ios_hostname: {config: {hostname: edge.lab}}":               "the ios_hostname step refuses",
		"cisco.ios.ios_hostname: {config: {hostname: '123'}}":                  "the ios_hostname step refuses",
		"arista.eos.eos_hostname: {config: {hostname: leaf_1}}":                "the eos_hostname step refuses",
		"junipernetworks.junos.junos_hostname: {config: {hostname: sw_1}}":     "the junos_hostname step refuses",
		"vyos.vyos.vyos_hostname: {config: {hostname: r1.lab}}":                "the vyos_hostname step refuses",
		// merged leaves a VLAN's name, and a step without one resets it.
		"arista.eos.eos_vlans: {config: [{vlan_id: 10}]}":                                                                         "without a name under state: merged",
		"cisco.ios.ios_vlans: {config: [{vlan_id: 10}], state: merged}":                                                           "or use state: replaced",
		"cisco.ios.ios_vlans: {config: [{vlan_id: 1002, name: x}]}":                                                               "IOS keeps for itself",
		"cisco.ios.ios_vlans: {config: [{vlan_id: 10, name: 'two words'}]}":                                                       "one word",
		"cisco.ios.ios_vlans: {config: [{vlan_id: 10, name: users, mtu: 1500}]}":                                                  "sets mtu",
		"cisco.ios.ios_vlans: {config: [{vlan_id: 10, name: users, state: suspend}]}":                                             "state to suspend",
		"arista.eos.eos_vlans: {config: [{vlan_id: 10, state: suspend}]}":                                                         "state to suspend",
		"junipernetworks.junos.junos_vlans: {config: [{name: users, vlan_id: 10, l3_interface: irb.10}]}":                         "sets l3_interface",
		"junipernetworks.junos.junos_vlans: {config: [{name: users}]}":                                                            "without a vlan_id",
		"arista.eos.eos_vlans: {config: [{vlan_id: 5000}]}":                                                                       "without a vlan_id from 1 to 4094",
		"cisco.ios.ios_interfaces: {config: [{name: Gi1/0/1, description: x}]}":                                                   "is not an interface name",
		"cisco.ios.ios_interfaces: {config: [{name: GigabitEthernet1, mode: layer3}]}":                                            "sets mode",
		"cisco.ios.ios_l2_interfaces: {config: [{name: GigabitEthernet1, mode: dynamic_auto}]}":                                   "sets mode dynamic_auto",
		"cisco.ios.ios_l2_interfaces: {config: [{name: GigabitEthernet1, trunk: {native_vlan: 99}}]}":                             "sets trunk native_vlan",
		"cisco.ios.ios_l2_interfaces: {config: [{name: GigabitEthernet1, trunk: {allowed_vlans: ['1-99999']}}], state: replaced}": "from 1 to 4094",
		// merged adds to a trunk's list, and the step owns all of it.
		"cisco.ios.ios_l2_interfaces: {config: [{name: GigabitEthernet1, trunk: {allowed_vlans: ['30']}}]}":                "write every VLAN the trunk should carry",
		"cisco.ios.ios_l2_interfaces: {config: [{name: GigabitEthernet1, trunk: {allowed_vlans: ['30']}}], state: merged}": "write every VLAN the trunk should carry",
		"cisco.ios.ios_l2_interfaces: {config: [{name: GigabitEthernet1, voice: {vlan: 20}}]}":                             "sets voice",
		"cisco.ios.ios_l2_interfaces: {config: [{name: Vlan20, mode: access, access: {vlan: 10}}]}":                        "switchport settings",
		"cisco.ios.ios_l2_interfaces: {config: [{name: GigabitEthernet1, mode: trunk, access: {vlan: 10}}]}":               "access_vlan is for mode",
		"arista.eos.eos_interfaces: {config: [{name: Ethernet1, speed: 10g}]}":                                             "sets speed",
		"vyos.vyos.vyos_l3_interfaces: {config: [{name: eth1, vifs: [{vlan_id: 10}]}]}":                                    "sets vifs",
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

func TestConvertNetworkRoutesAndUsers(t *testing.T) {
	for task, want := range map[string][]string{
		"junipernetworks.junos.junos_static_routes: {config: [{address_families: [{afi: ipv4, routes: [{dest: 0.0.0.0/0, next_hop: [{forward_router_address: 192.0.2.254}]}]}]}], state: replaced}": {
			"junos_static_route {", `prefix    = "0.0.0.0/0"`, `next_hops = ["192.0.2.254"]`},
		"vyos.vyos.vyos_static_routes: {config: [{address_families: [{afi: ipv4, routes: [{dest: 10.0.0.0/8, next_hops: [{forward_router_address: 192.0.2.1, admin_distance: 10}, {forward_router_address: 192.0.2.2, admin_distance: 10}]}]}]}], state: replaced}": {
			"vyos_static_route {", `next_hops = ["192.0.2.1", "192.0.2.2"]`, "distance  = 10"},
		"cisco.ios.ios_static_routes: {config: [{address_families: [{afi: ipv4, routes: [{dest: 0.0.0.0/0, next_hops: [{forward_router_address: 192.0.2.1, distance_metric: 5}, {forward_router_address: 192.0.2.2, distance_metric: 5}]}]}]}], state: replaced}": {
			"ios_static_route {", `next_hops = ["192.0.2.1", "192.0.2.2"]`, "distance  = 5"},
		"cisco.ios.ios_static_routes: {config: [{address_families: [{afi: ipv6, routes: [{dest: '2001:db8:20::/48', next_hops: [{forward_router_address: '2001:db8::1'}]}]}]}], state: replaced}": {
			"ios_static_route {", `prefix    = "2001:db8:20::/48"`},
		"arista.eos.eos_static_routes: {config: [{address_families: [{afi: ipv4, routes: [{dest: 10.20.0.0/16, next_hops: [{forward_router_address: 192.0.2.1, admin_distance: 200}]}]}]}], state: replaced}": {
			"eos_static_route {", `prefix    = "10.20.0.0/16"`, "distance  = 200"},
		"arista.eos.eos_user: {name: ops, role: network-admin, privilege: 15, sshkey: 'ssh-ed25519 AAAA ops'}": {
			"eos_user {", `role      = "network-admin"`, "privilege = 15", `ssh_key   = "ssh-ed25519 AAAA ops"`},
		"junipernetworks.junos.junos_user: {name: alice, role: operator}": {"junos_user {", `class = "operator"`},
		"vyos.vyos.vyos_user: {name: alice, full_name: Alice, public_keys: [{name: alice@laptop, key: AAAA, type: ssh-ed25519}]}": {
			"vyos_user {", `full_name = "Alice"`, `ssh_keys  = ["ssh-ed25519 AAAA alice@laptop"]`},
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

	// A configured_password becomes a TODO, and its value isn't copied.
	res := convertString(t, netPlay+"    - arista.eos.eos_user: {name: ops, role: network-admin, configured_password: Hunter2-secret}\n")
	if hcl := string(res.HCL); strings.Contains(hcl, "Hunter2") || !strings.Contains(hcl, "TODO(convert): Set password_wo") {
		t.Errorf("configured_password:\n%s", hcl)
	}

	for task, reason := range map[string]string{
		"junipernetworks.junos.junos_static_routes: {config: [{address_families: [{afi: ipv6, routes: [{dest: '::/0', next_hop: [{forward_router_address: '2001:db8::1'}]}]}]}]}":                                                               "takes IPv4 routes only",
		"junipernetworks.junos.junos_static_routes: {config: [{vrf: blue, address_families: [{afi: ipv4, routes: [{dest: 0.0.0.0/0, next_hop: [{forward_router_address: 192.0.2.1}]}]}]}]}":                                                     "sets vrf",
		"junipernetworks.junos.junos_static_routes: {config: [{address_families: [{afi: ipv4, routes: [{dest: 0.0.0.0/0, metric: 5, next_hop: [{forward_router_address: 192.0.2.1}]}]}]}]}":                                                     "sets metric",
		"vyos.vyos.vyos_static_routes: {config: [{address_families: [{afi: ipv4, routes: [{dest: 0.0.0.0/0, blackhole_config: {type: blackhole}}]}]}]}":                                                                                         "sets blackhole_config",
		"vyos.vyos.vyos_static_routes: {config: [{address_families: [{afi: ipv4, routes: [{dest: 0.0.0.0/0, next_hops: [{forward_router_address: 192.0.2.1, admin_distance: 1}, {forward_router_address: 192.0.2.2, admin_distance: 5}]}]}]}]}": "different admin_distance",
		"vyos.vyos.vyos_static_routes: {config: [{address_families: [{afi: ipv4, routes: [{dest: 0.0.0.0/0, next_hops: [{interface: eth0}]}]}]}]}":                                                                                              "sets interface",
		"arista.eos.eos_user: {aggregate: [{name: a}, {name: b}]}": "sets aggregate",
		"arista.eos.eos_user: {name: ops, state: absent}":          "has state absent",
		// merged and junos_user add to a list the step owns whole.
		"junipernetworks.junos.junos_user: {name: alice, role: operator, sshkey: 'ssh-ed25519 AAAA alice'}":                                                                                                                                                       "list every key the account should have",
		"junipernetworks.junos.junos_static_routes: {config: [{address_families: [{afi: ipv4, routes: [{dest: 0.0.0.0/0, next_hop: [{forward_router_address: 192.0.2.254}]}]}]}]}":                                                                                "or use state: replaced",
		"vyos.vyos.vyos_static_routes: {config: [{address_families: [{afi: ipv4, routes: [{dest: 10.0.0.0/8, next_hops: [{forward_router_address: 192.0.2.1}]}]}]}], state: merged}":                                                                              "or use state: replaced",
		"vyos.vyos.vyos_l3_interfaces: {config: [{name: eth1, ipv4: [{address: 192.0.2.1/24}]}]}":                                                                                                                                                                 "write every address eth1 should have",
		"cisco.ios.ios_static_routes: {config: [{address_families: [{afi: ipv4, routes: [{dest: 0.0.0.0/0, next_hops: [{forward_router_address: 192.0.2.1}]}]}]}]}":                                                                                               "or use state: replaced",
		"arista.eos.eos_static_routes: {config: [{address_families: [{afi: ipv4, routes: [{dest: 0.0.0.0/0, next_hops: [{forward_router_address: 192.0.2.1}]}]}]}], state: merged}":                                                                               "or use state: replaced",
		"cisco.ios.ios_static_routes: {config: [{vrf: blue, address_families: [{afi: ipv4, routes: [{dest: 0.0.0.0/0, next_hops: [{forward_router_address: 192.0.2.1}]}]}]}], state: replaced}":                                                                   "sets vrf",
		"cisco.ios.ios_static_routes: {config: [{address_families: [{afi: ipv4, routes: [{dest: 0.0.0.0/0, next_hops: [{interface: Null0}]}]}]}], state: replaced}":                                                                                               "sets interface",
		"cisco.ios.ios_static_routes: {config: [{address_families: [{afi: ipv4, routes: [{dest: 0.0.0.0/0, next_hops: [{forward_router_address: 192.0.2.1, distance_metric: 1}, {forward_router_address: 192.0.2.2, distance_metric: 5}]}]}]}], state: replaced}": "different distance_metric",
		"arista.eos.eos_static_routes: {config: [{address_families: [{afi: ipv4, routes: [{dest: 10.0.0.1/8, next_hops: [{forward_router_address: 192.0.2.1}]}]}]}], state: replaced}":                                                                            "host bits",
		"junipernetworks.junos.junos_user: {name: alice}":                                        "has no role",
		"vyos.vyos.vyos_user: {name: alice, encrypted_password: '$6$x'}":                         "sets encrypted_password",
		"vyos.vyos.vyos_user: {name: alice, configured_password: x, update_password: on_create}": "update_password: on_create",
	} {
		res := convertString(t, netPlay+"    - "+task+"\n")
		if res.Converted != 0 || !strings.Contains(reasons(res), reason) {
			t.Errorf("%s: converted %d, review %q, want %q", task, res.Converted, reasons(res), reason)
		}
	}
}

// IOS's and EOS's replaced removes the address family's other routes too,
// which the converted steps don't, so the first step says so.
func TestConvertNetworkRoutesReplacedNote(t *testing.T) {
	res := convertString(t, netPlay+"    - cisco.ios.ios_static_routes: {config: [{address_families: [{afi: ipv4, routes: [{dest: 0.0.0.0/0, next_hops: [{forward_router_address: 192.0.2.1}]}, {dest: 10.0.0.0/8, next_hops: [{forward_router_address: 192.0.2.2}]}]}]}], state: replaced}\n")
	if res.Converted != 1 || len(res.Notes) != 1 || !strings.Contains(res.Notes[0].Reason, "on_remove") {
		t.Errorf("converted %d, notes %+v\n%s", res.Converted, res.Notes, res.HCL)
	}
	if n := strings.Count(string(res.HCL), "other static routes"); n != 1 {
		t.Errorf("the note appears %d times:\n%s", n, res.HCL)
	}
	junos := convertString(t, netPlay+"    - junipernetworks.junos.junos_static_routes: {config: [{address_families: [{afi: ipv4, routes: [{dest: 0.0.0.0/0, next_hop: [{forward_router_address: 192.0.2.1}]}]}]}], state: replaced}\n")
	if len(junos.Notes) != 0 {
		t.Errorf("junos's replaced only touches the named routes, but got %+v", junos.Notes)
	}
}
