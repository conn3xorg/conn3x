// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// More of each Windows module's arguments.
func TestWindowsMoreMappings(t *testing.T) {
	for task, wants := range map[string][]string{
		`win_wait_for: {path: 'C:\x', host: localhost}`:                                               {"windows_wait_for {", `path = "C:\\x"`},
		`win_acl: {path: 'C:\x', user: u, rights: Read, inherit: None}`:                               {`inheritance = "none"`},
		`win_acl: {path: 'C:\x', user: u, rights: Read, inherit: ObjectInherit}`:                      {`inheritance = "object"`},
		`win_regedit: {path: 'HKEY_LOCAL_MACHINE:\SOFTWARE\App', name: N, data: x}`:                   {`key  = "HKLM\\SOFTWARE\\App"`, `type = "string"`},
		`win_regedit: {path: 'HKLM:\SOFTWARE\App', name: Q, data: 42, type: qword}`:                   {`type = "qword"`, `data = "42"`},
		`win_service: {name: a, start_mode: delayed}`:                                                 {`start_mode = "delayed"`},
		`win_service: {name: a, start_mode: manual, state: stopped}`:                                  {`start_mode = "manual"`, `state      = "stopped"`},
		`win_service: {name: a, start_mode: disabled}`:                                                {`start_mode = "disabled"`},
		`win_firewall_rule: {name: Out, localport: 53, protocol: udp, direction: out, action: allow}`: {`direction   = "outbound"`},
		`win_scheduled_task: {name: a, username: SYSTEM, logon_type: service_account, enabled: no, actions: [{path: 'C:\a.exe', working_directory: 'C:\w'}]}`: {
			`working_directory = "C:\\w"`, "enabled           = false"},
		`win_scheduled_task: {name: a, username: app, logon_type: s4u, actions: [{path: 'C:\a.exe'}]}`: {"windows_scheduled_task {"},
		`microsoft.iis.website: {name: s, physical_path: 'C:\s', bindings: {set: [{port: 80, ip: '10.0.0.4'}, {port: 81, ip: '*'}]}}`: {
			`ip   = "10.0.0.4"`, "port = 81"},
		`microsoft.ad.group: {name: g, scope: Global, category: Security}`:                    {"windows_ad_group {", `scope    = "global"`, `category = "security"`},
		`microsoft.ad.group: {name: g, scope: global, members: {add: []}}`:                    {"windows_ad_group {"},
		`microsoft.ad.group: {name: g, scope: global, members: {set: []}}`:                    {"members       = []", "authoritative = true"},
		`microsoft.ad.group: {name: g, scope: global, members: {add: [alice, 'web1$']}}`:      {`members = ["alice", "web1$"]`},
		`win_updates: {category_names: [SecurityUpdates], accept_list: [KB5034441]}`:          {"windows_update {", `accept_list = ["KB5034441"]`},
		`win_updates: {state: installed, category_names: [SecurityUpdates], reject_list: []}`: {"windows_update {"},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
			continue
		}
		for _, w := range wants {
			if !strings.Contains(string(res.HCL), w) {
				t.Errorf("%s: output lacks %q:\n%s", task, w, res.HCL)
			}
		}
	}
	// state searched changes nothing and leaves only a note.
	if res := convertString(t, "- hosts: all\n  tasks:\n    - win_updates: {state: searched}\n"); len(res.Review) != 0 || strings.Contains(string(res.HCL), "windows_update {") {
		t.Errorf("searched: review %+v:\n%s", res.Review, res.HCL)
	}
}

func TestWindowsMoreLeftForAPerson(t *testing.T) {
	for task, reason := range map[string]string{
		`win_shell: {creates: 'C:\x'}`:                                                                                  "has no script or command",
		`win_wait_for: {host: db1, port: 1433}`:                                                                         "waits for another host",
		`win_wait_for: {port: 80, timeout: soon}`:                                                                       "has a timeout that isn't a number of seconds",
		`win_copy: {dest: 'C:\x'}`:                                                                                      "has neither content nor src",
		`win_acl: {path: 'C:\x', user: u, rights: Read}` + "\n      loop: [a]":                                          "loops, and a rule's entry can't take a loop value",
		`win_acl: {path: 'C:\x', user: u}`:                                                                              "lists no rights",
		`win_acl: {path: 'C:\x', user: u, rights: Read, type: maybe}`:                                                   `has a type "maybe" that isn't allow or deny`,
		`win_acl: {path: 'C:\x', user: u, rights: Read, inherit: Sideways}`:                                             `has an inherit value "Sideways"`,
		`win_regedit: {path: 'HKLM:\x', name: a, data: b, type: none}`:                                                  `has the type "none"`,
		`win_regedit: {path: 'HKLM:\x', name: a, data: [b], type: string}`:                                              "gives a list as data for a type that holds one value",
		`win_service: {name: a, start_mode: boot}`:                                                                      `has the start_mode "boot"`,
		`win_service: {name: a}`:                                                                                        "sets neither start_mode nor state",
		`win_group_membership: {name: a, members: []}`:                                                                  "lists no members",
		`win_firewall_rule: {name: a, localport: 80, protocol: tcp, direction: sideways}`:                               `has the direction "sideways"`,
		`win_scheduled_task: {name: a, username: SYSTEM, actions: [{path: 'C:\a.exe', bogus: 1}]}`:                      "sets bogus in actions",
		`win_scheduled_task: {name: a, username: SYSTEM, logon_type: interactive_token, actions: [{path: 'C:\a.exe'}]}`: `has the logon_type "interactive_token"`,
		`win_scheduled_task: {name: a, username: SYSTEM, actions: [{path: 'C:\a.exe'}], triggers: [{type: daily, days_interval: often}]}`: "has a days_interval that isn't a number",
		`win_iis_webapppool: {name: a, attributes: 'autoStart:false'}`:                                                                    "gives attributes as text; write them as a map",
		`win_iis_website: {name: a, physical_path: 'C:\x', state: restarted, port: 80}`:                                                   "restarts it on every run",
		`win_iis_website: {name: a, physical_path: 'C:\x', port: http}`:                                                                   "has a port that isn't a number",
		`win_iis_website: {name: a, port: 80}`:                                                                                            "has no physical_path; windows_iis_site needs one",
		`microsoft.iis.website: {name: a, physical_path: 'C:\x', state: restarted}`:                                                       "restarts it on every run",
		`microsoft.iis.website: {name: a, physical_path: 'C:\x', bindings: {set: [{port: 80, x: 1}]}}`:                                    "sets x in bindings",
		`microsoft.iis.website: {name: a, physical_path: 'C:\x', bindings: {set: [{port: web}]}}`:                                         "has a binding without a numeric port",
		`microsoft.iis.website: {name: a, physical_path: 'C:\x', bindings: {set: []}}`:                                                    "has no bindings; a windows_iis_site needs at least one",
		`win_updates: {state: downloaded}`:                                                                                                "only downloads updates",
		`microsoft.ad.domain_child: {dns_domain_name: emea.lab.test, domain_admin_user: a@lab.test, domain_type: forest}`:                 `has domain_type "forest"`,
		`microsoft.ad.group: {name: g, scope: global, members: [a]}`:                                                                      "gives members that aren't add, set or remove lists",
		`microsoft.ad.group: {name: g, scope: global, members: {remove: [a]}}`:                                                            "takes members out by name",
		`microsoft.ad.group: {name: g, scope: global, members: {add: [a], lookup_failure_action: warn}}`:                                  "sets lookup_failure_action warn",
		`microsoft.ad.group: {name: g, scope: global, members: {add: [a], set: [b]}}`:                                                     "both adds and sets members",
		`microsoft.ad.group: {name: g, scope: global, members: {add: [a], other: 1}}`:                                                     "sets other in members",
		`microsoft.ad.group: {name: g, scope: global, members: {add: ['CN=a,DC=lab']}}`:                                                   "names a member by something other than its sAMAccountName",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, reason)
		}
	}
}
