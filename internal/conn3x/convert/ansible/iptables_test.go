// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ansible.builtin.iptables becomes an iptables_rule step, argument for
// argument, or two for ip_version: both. What changes a whole chain, or
// needs an option the step doesn't carry, stays for review.
func TestConvertIPTables(t *testing.T) {
	play := filepath.Join(t.TempDir(), "play.yml")
	convert := func(task string) Result {
		t.Helper()
		if err := os.WriteFile(play, []byte("- hosts: all\n  tasks:\n    - "+task+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := Convert(play)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	for task, want := range map[string][]string{
		`ansible.builtin.iptables: {chain: INPUT, protocol: tcp, destination_port: "22", jump: ACCEPT}`: {
			"iptables_rule {", `chain            = "INPUT"`, `protocol         = "tcp"`, `destination_port = "22"`, `jump             = "ACCEPT"`,
		},
		`iptables: {table: nat, chain: POSTROUTING, out_interface: eth0, source: 10.0.0.0/8, jump: MASQUERADE}`: {
			`table         = "nat"`, `out_interface = "eth0"`, `source        = "10.0.0.0/8"`,
		},
		`iptables: {chain: INPUT, protocol: udp, source_port: "53", destination: 192.0.2.1, in_interface: eth1, jump: DROP}`: {
			`source_port  = "53"`, `destination  = "192.0.2.1"`, `in_interface = "eth1"`,
		},
		`iptables: {chain: INPUT, protocol: tcp, destination_ports: ["80", "443:445"], match: multiport, jump: ACCEPT}`: {
			`destination_ports = ["80", "443:445"]`,
		},
		`iptables: {chain: INPUT, ctstate: [ESTABLISHED, RELATED], match: conntrack, jump: ACCEPT, action: insert, rule_num: "1"}`: {
			`ctstate  = ["ESTABLISHED", "RELATED"]`, `position = "insert"`, "rule_num = 1",
		},
		`iptables: {chain: INPUT, protocol: tcp, match: tcp, destination_port: "443", jump: ACCEPT, comment: "it's \"https\"", wait: "5"}`: {
			`comment          = "it's \"https\""`,
		},
		`iptables: {chain: INPUT, source: "2001:db8::/32", jump: DROP, ip_version: ipv6}`: {
			`ip_version = "ipv6"`, `source     = "2001:db8::/32"`,
		},
		`iptables: {chain: INPUT, ctstate: ESTABLISHED, jump: ACCEPT, action: append, rule_num: "4"}`: {
			`ctstate = ["ESTABLISHED"]`,
		},
	} {
		res := convert(task)
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v\n%s", task, res.Converted, res.Review, res.HCL)
			continue
		}
		for _, w := range want {
			if !strings.Contains(string(res.HCL), w) {
				t.Errorf("%s: missing %q:\n%s", task, w, res.HCL)
			}
		}
		if strings.Contains(task, "action: append") && (strings.Contains(string(res.HCL), "rule_num") || strings.Contains(string(res.HCL), "position")) {
			t.Errorf("%s: rule_num only counts with insert:\n%s", task, res.HCL)
		}
	}

	res := convert(`iptables: {chain: INPUT, protocol: tcp, destination_port: "22", jump: ACCEPT, ip_version: both}`)
	if res.Converted != 1 || len(res.Review) != 0 || strings.Count(string(res.HCL), "iptables_rule {") != 2 ||
		!strings.Contains(string(res.HCL), `ip_version       = "ipv4"`) || !strings.Contains(string(res.HCL), `ip_version       = "ipv6"`) {
		t.Errorf("both: converted %d, review %+v\n%s", res.Converted, res.Review, res.HCL)
	}

	for task, reason := range map[string]string{
		`iptables: {chain: INPUT, policy: DROP}`:                                                       "chain's policy",
		`iptables: {chain: INPUT, flush: true}`:                                                        "flushes a chain",
		`iptables: {chain: APP, chain_management: true}`:                                               "creates or deletes a chain",
		`iptables: {chain: INPUT, goto: APP}`:                                                          "goto",
		`iptables: {table: nat, chain: PREROUTING, protocol: tcp, jump: REDIRECT, to_ports: "8080"}`:   "to_ports",
		`iptables: {table: nat, chain: PREROUTING, jump: DNAT, to_destination: "10.0.0.2:80"}`:         "to_destination",
		`iptables: {chain: INPUT, protocol: tcp, destination_port: "22", limit: 3/minute}`:             "limit",
		`iptables: {chain: INPUT, protocol: tcp, destination_port: "22", jump: ACCEPT, state: absent}`: "state: absent",
		`iptables: {chain: INPUT, match: state, state: present, jump: ACCEPT}`:                         "match state",
		`iptables: {chain: INPUT, source: "!10.0.0.0/8", jump: DROP}`:                                  "negates source",
		`iptables: {chain: INPUT, source: 10.0.0.0/8, jump: DROP, ip_version: both}`:                   "not an ipv6 address",
		`iptables: {chain: INPUT, destination_port: "22", jump: ACCEPT}`:                               "needs protocol",
		`iptables: {chain: INPUT, source: example.com, jump: ACCEPT}`:                                  "not an address or CIDR",
		`iptables: {chain: INPUT, jump: REJECT, reject_with: tcp-reset}`:                               "reject_with",
		`iptables: {chain: INPUT, jump: ACCEPT, action: insert, rule_num: first}`:                      "rule_num that isn't a whole number",
		`iptables: {chain: INPUT, jump: ACCEPT, ip_version: ipv5}`:                                     "ip_version",
		`iptables: {chain: "{{ fw_chain }}", jump: ACCEPT}`:                                            "fw_chain",
		`iptables: {jump: ACCEPT}`:                                                                     "chain",
	} {
		res := convert(task)
		if res.Converted != 0 || !strings.Contains(reasons(res), reason) {
			t.Errorf("%s: converted %d, review %q, want %q\n%s", task, res.Converted, reasons(res), reason, res.HCL)
		}
	}
}
