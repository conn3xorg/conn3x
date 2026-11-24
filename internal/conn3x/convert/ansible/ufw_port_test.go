// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// A ufw or firewalld task converts only to a step that passes the step's
// own Validate; anything else, such as a service name ufw would look up in
// the host's /etc/services, stays for review with the reason (#1341).
func TestConvertFirewallPorts(t *testing.T) {
	for task, want := range map[string][]string{
		"ufw: {rule: allow, port: '22'}":                                     {`port = "22"`},
		"ufw: {rule: limit, port: '22', proto: tcp}":                         {`action = "limit"`, `port = "22/tcp"`},
		"ufw: {rule: allow, port: '6000:6007', proto: tcp}":                  {`port = "6000:6007/tcp"`},
		"ufw: {rule: allow, port: '22', from_ip: any}":                       {`port = "22"`},
		"firewalld: {port: 8080/tcp, permanent: yes, immediate: yes}":        {`port = "8080/tcp"`},
		"firewalld: {port: 60000-61000/udp, permanent: yes, immediate: yes}": {`port = "60000-61000/udp"`},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		hcl := strings.Join(strings.Fields(string(res.HCL)), " ")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
			continue
		}
		for _, w := range want {
			if !strings.Contains(hcl, w) {
				t.Errorf("%s: missing %q:\n%s", task, w, res.HCL)
			}
		}
		if strings.Contains(hcl, `from =`) {
			t.Errorf("%s: from any should leave from out:\n%s", task, res.HCL)
		}
	}
	for task, reason := range map[string]string{
		"community.general.ufw: {rule: limit, port: ssh, proto: tcp}":                 `port "ssh/tcp", a service name ufw looks up in the host's /etc/services; write the port number`,
		"ufw: {rule: allow, port: http}":                                              `port "http", a service name`,
		"ufw: {rule: allow, port: '6000:6007'}":                                       "port range \"6000:6007\" needs a protocol",
		"ufw: {rule: allow, port: '70000', proto: tcp}":                               "out of range",
		"ufw: {rule: allow, from_ip: 10.0.0.0/8}":                                     "has no port",
		"ufw: {rule: allow, port: '22', from_ip: not-an-address}":                     "is not an address or CIDR",
		"firewalld: {port: http/tcp, permanent: yes, immediate: yes}":                 `port "http/tcp", a service name firewalld looks up`,
		"firewalld: {port: '8080', permanent: yes, immediate: yes}":                   "must look like 8080/tcp",
		"firewalld: {zone: public, permanent: yes, immediate: yes}":                   "set exactly one of service, port, rich_rule or source",
		"ufw: {rule: allow, port: '{{ item }}', proto: tcp}\n      loop: ['22', ssh]": `for that item: has port "ssh/tcp"`,
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, reason)
		}
	}
	// A loop over written numbers still converts: each item is checked alone.
	res := convertString(t, "- hosts: all\n  tasks:\n    - ufw: {rule: allow, port: '{{ item }}', proto: tcp}\n      loop: ['80', '443']\n")
	if res.Converted != 1 || len(res.Review) != 0 || !strings.Contains(string(res.HCL), `"${item.value}/tcp"`) {
		t.Errorf("loop: converted %d, review %+v:\n%s", res.Converted, res.Review, res.HCL)
	}
}
