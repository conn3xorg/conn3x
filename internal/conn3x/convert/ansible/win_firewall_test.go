// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertWinFirewall(t *testing.T) {
	res := convertString(t, "- hosts: all\n  tasks:\n    - community.windows.win_firewall: {state: enabled, inbound_action: block, outbound_action: allow}\n")
	if n := strings.Count(string(res.HCL), "windows_firewall_profile {"); res.Converted != 1 || n != 3 {
		t.Fatalf("all profiles by default: converted %d, %d steps:\n%s", res.Converted, n, res.HCL)
	}
	for _, w := range []string{`name             = "domain"`, `name             = "private"`, `name             = "public"`, "enabled          = true", `default_inbound  = "block"`, `default_outbound = "allow"`} {
		if !strings.Contains(string(res.HCL), w) {
			t.Errorf("missing %s in:\n%s", w, res.HCL)
		}
	}
	res = convertString(t, "- hosts: all\n  tasks:\n    - win_firewall: {profiles: [Public], state: disabled}\n")
	if n := strings.Count(string(res.HCL), "windows_firewall_profile {"); n != 1 || !strings.Contains(string(res.HCL), `name    = "public"`) || !strings.Contains(string(res.HCL), "enabled = false") {
		t.Errorf("one profile, disabled:\n%s", res.HCL)
	}
	for task, reason := range map[string]string{
		"community.windows.win_firewall: {inbound_action: not_configured}":   "takes allow or block",
		"community.windows.win_firewall: {profiles: [Work], state: enabled}": `profile "work"`,
		"community.windows.win_firewall: {profiles: [Public]}":               "changes nothing",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}
