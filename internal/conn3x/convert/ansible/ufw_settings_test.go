// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// A ufw task without a rule changes ufw itself, and becomes a ufw_settings
// step. default without a direction is incoming, as Ansible reads it.
func TestConvertUFWSettings(t *testing.T) {
	for task, want := range map[string][]string{
		"ufw: {state: enabled}":                            {"ufw_settings {", "enabled = true"},
		"ufw: {state: disabled}":                           {"enabled = false"},
		"ufw: {default: deny}":                             {`default_incoming = "deny"`},
		"ufw: {policy: reject, direction: incoming}":       {`default_incoming = "reject"`},
		"ufw: {default: allow, direction: outgoing}":       {`default_outgoing = "allow"`},
		"ufw: {default: deny, direction: routed}":          {`default_routed = "deny"`},
		"ufw: {state: enabled, default: deny}":             {"enabled = true", `default_incoming = "deny"`},
		"community.general.ufw: {rule: allow, port: '22'}": {"ufw {", `action = "allow"`},
		"ufw: {state: enabled, logging: 'on'}":             {"enabled = true", `logging = "on"`},
		"ufw: {logging: 'off'}":                            {`logging = "off"`},
		"ufw: {logging: low}":                              {`logging = "low"`},
		"ufw: {logging: medium}":                           {`logging = "medium"`},
		"ufw: {logging: high}":                             {`logging = "high"`},
		"ufw: {logging: full}":                             {`logging = "full"`},
		// Bare, YAML reads these as booleans, which Ansible maps to on and off.
		"ufw: {logging: on}":     {`logging = "on"`},
		"ufw: {logging: yes}":    {`logging = "on"`},
		"ufw: {logging: true}":   {`logging = "on"`},
		"ufw: {logging: off}":    {`logging = "off"`},
		"ufw: {logging: no}":     {`logging = "off"`},
		"ufw: {logging: False}":  {`logging = "off"`},
		"ufw: {logging: 'True'}": {`logging = "on"`},
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
	}
	for task, reason := range map[string]string{
		"ufw: {state: reset}":                 "has state reset",
		"ufw: {default: deny, direction: in}": "direction in, which Ansible refuses",
		"ufw: {logging: 'yes'}":               "sets logging \"yes\"",
		"ufw: {logging: verbose}":             "sets logging \"verbose\"",
		"ufw: {logging: 'ON'}":                "sets logging \"ON\"",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, reason)
		}
	}
}
