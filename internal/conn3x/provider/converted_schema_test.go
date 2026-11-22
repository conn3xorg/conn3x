// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/opentofu/opentofu/internal/configs"
	"github.com/opentofu/opentofu/internal/conn3x/convert/ansible"
)

// A converted step has to have arguments its step type takes: the
// converter's own tests only check the output is HCL, so a misspelt
// argument there only shows at validate. Each task here is one the
// converter turns into a step; every step it writes is checked against its
// resource type's schema.
func TestConvertedStepsFitTheirSchemas(t *testing.T) {
	const playbook = `- hosts: all
  tasks:
    - community.postgresql.postgresql_pg_hba: {dest: /etc/postgresql/17/main/pg_hba.conf, contype: host, users: app, databases: app, source: 10.0.0.0/24, method: scram-sha-256, create: true}
    - community.postgresql.postgresql_pg_hba: {dest: /etc/pg_hba.conf, contype: local, users: app, method: peer, state: absent}
    - community.postgresql.postgresql_alter_system: {param: work_mem, value: 64MB}
    - community.mysql.mysql_variables: {variable: max_connections, value: 500, mode: persist}
    - ansible.builtin.lineinfile: {path: /etc/app.conf, line: "a=1", regexp: "^a=", insertbefore: "^b="}
    - ansible.windows.win_hostname: {name: WEB01}
    - ansible.windows.win_optional_feature: {name: TelnetClient}
    - community.windows.win_timezone: {timezone: UTC}
    - ansible.windows.win_get_url: {url: 'https://example.com/a.msi', dest: 'C:/Installers/a.msi', checksum: ec6af1ea0367d16dde6639a89a080a524cebc4d4bedfe00ed0cac4b865a918d8, checksum_algorithm: sha256}
    - community.windows.win_firewall: {profiles: [public], state: enabled, inbound_action: block, outbound_action: allow}
    - ansible.windows.win_user_right: {name: SeServiceLogonRight, users: [svc_app], action: add}
    - chocolatey.chocolatey.win_chocolatey: {name: git, version: 2.44.0, source: 'https://nuget.example.com/v3/index.json', pinned: true}
    - ansible.windows.win_lineinfile: {path: 'C:/app/app.ini', line: 'a=1', regexp: '^a=', insertbefore: '^b='}
    - ansible.builtin.get_url: {url: "https://example.com/a.tgz", dest: /opt/a.tgz, checksum: "sha256:0000000000000000000000000000000000000000000000000000000000000000", headers: {Accept: application/octet-stream}}
- hosts: switches
  connection: network_cli
  tasks:
    - cisco.ios.ios_config: {parents: ["interface GigabitEthernet1"], lines: ["description uplink"]}
    - cisco.ios.ios_hostname: {config: {hostname: edge01}}
    - cisco.ios.ios_interfaces: {config: [{name: GigabitEthernet1/0/1, description: uplink, enabled: true}]}
    - cisco.ios.ios_l2_interfaces: {config: [{name: GigabitEthernet1/0/2, mode: access, access: {vlan: 10}}]}
    - cisco.ios.ios_l2_interfaces: {config: [{name: GigabitEthernet1/0/3, mode: trunk, trunk: {allowed_vlans: ['10-12']}}], state: replaced}
    - arista.eos.eos_config: {parents: ["interface Ethernet1"], lines: ["description uplink"]}
    - junipernetworks.junos.junos_config: {lines: ["set system ntp server 192.0.2.10"]}
    - vyos.vyos.vyos_config: {lines: ["set system ntp server 192.0.2.10"]}
    - arista.eos.eos_hostname: {config: {hostname: leaf1}}
    - arista.eos.eos_vlans: {config: [{vlan_id: 10, name: users}]}
    - junipernetworks.junos.junos_vlans: {config: [{name: users, vlan_id: 10}]}
    - cisco.ios.ios_vlans: {config: [{vlan_id: 10, name: users}]}
    - arista.eos.eos_interfaces: {config: [{name: Ethernet1, description: uplink, mtu: 9000, enabled: true}]}
    - junipernetworks.junos.junos_interfaces: {config: [{name: ge-0/0/1, description: uplink, mtu: 9000}]}
    - vyos.vyos.vyos_interfaces: {config: [{name: eth1, description: uplink, mtu: 1500}]}
    - vyos.vyos.vyos_l3_interfaces: {config: [{name: eth1, ipv4: [{address: 192.0.2.1/24}]}], state: replaced}
    - junipernetworks.junos.junos_hostname: {config: {hostname: sw1}}
    - vyos.vyos.vyos_hostname: {config: {hostname: r1}}
    - junipernetworks.junos.junos_static_routes: {config: [{address_families: [{afi: ipv4, routes: [{dest: 0.0.0.0/0, next_hop: [{forward_router_address: 192.0.2.254}]}]}]}], state: replaced}
    - vyos.vyos.vyos_static_routes: {config: [{address_families: [{afi: ipv4, routes: [{dest: 10.0.0.0/8, next_hops: [{forward_router_address: 192.0.2.1, admin_distance: 10}]}]}]}], state: replaced}
    - cisco.ios.ios_static_routes: {config: [{address_families: [{afi: ipv4, routes: [{dest: 0.0.0.0/0, next_hops: [{forward_router_address: 192.0.2.1, distance_metric: 5}]}]}]}], state: replaced}
    - arista.eos.eos_static_routes: {config: [{address_families: [{afi: ipv6, routes: [{dest: '2001:db8:20::/48', next_hops: [{forward_router_address: '2001:db8::1'}]}]}]}], state: replaced}
    - arista.eos.eos_user: {name: ops, role: network-admin, privilege: 15, sshkey: "ssh-ed25519 AAAA ops", nopassword: false}
    - junipernetworks.junos.junos_user: {name: alice, role: operator}
    - vyos.vyos.vyos_user: {name: alice, full_name: Alice, public_keys: [{name: alice@laptop, key: AAAA, type: ssh-ed25519}]}
`
	path := filepath.Join(t.TempDir(), "play.yml")
	if err := os.WriteFile(path, []byte(playbook), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := ansible.Convert(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res.Review {
		t.Errorf("not converted: %s", r.Reason)
	}
	f, diags := hclsyntax.ParseConfig(res.HCL, "play.tf", hcl.InitialPos)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	checked := 0
	var walk func(*hclsyntax.Body)
	walk = func(b *hclsyntax.Body) {
		for _, blk := range b.Blocks {
			if typ, ok := configs.CircuitStepType(blk.Type); ok {
				rt, ok := resourceTypes[typ]
				if !ok {
					t.Errorf("%s: no resource type %s", blk.Type, typ)
					continue
				}
				schema := rt.schema().Block
				for name := range blk.Body.Attributes {
					if _, ok := schema.Attributes[name]; !ok {
						t.Errorf("%s step at %s: %s has no argument %q", blk.Type, blk.DefRange(), typ, name)
					}
				}
				checked++
				continue
			}
			walk(blk.Body)
		}
	}
	walk(f.Body.(*hclsyntax.Body))
	if checked < 39 {
		t.Errorf("checked %d steps, want every task's:\n%s", checked, res.HCL)
	}
}
