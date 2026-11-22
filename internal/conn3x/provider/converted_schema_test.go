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
    - arista.eos.eos_config: {parents: ["interface Ethernet1"], lines: ["description uplink"]}
    - junipernetworks.junos.junos_config: {lines: ["set system ntp server 192.0.2.10"]}
    - vyos.vyos.vyos_config: {lines: ["set system ntp server 192.0.2.10"]}
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
	if checked < 18 {
		t.Errorf("checked %d steps, want every task's:\n%s", checked, res.HCL)
	}
}
