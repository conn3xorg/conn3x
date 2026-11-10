// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// A playbook shaped like a real IIS role converts what it can and leaves the
// rest marked.
func TestConvertWindowsGolden(t *testing.T) {
	res := golden(t, "win")
	var tasks []string
	for _, r := range res.Review {
		tasks = append(tasks, r.Task)
	}
	want := []string{"Install IIS", "Reboot if IIS asked for it", "App settings", "Service account", "7-Zip", "Telnet client on test boxes only"}
	if res.Converted != 12 || strings.Join(tasks, "|") != strings.Join(want, "|") {
		t.Fatalf("converted %d, review %v", res.Converted, tasks)
	}
}

// A child domain converts with its reboot and the wait for AD; a new tree is
// left for a person. No password reaches the output.
func TestConvertChildDomainGolden(t *testing.T) {
	res := golden(t, "adchild")
	if res.Converted != 1 || len(res.Review) != 1 || res.Review[0].Task != "Same, as a new tree" {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
	if strings.Contains(string(res.HCL), "password }}") {
		t.Errorf("a password reference reached the output:\n%s", res.HCL)
	}
}

func TestWindowsMappings(t *testing.T) {
	for task, wants := range map[string][]string{
		`ansible.windows.win_file: {path: 'C:\app', state: directory}`: {"windows_directory {", `path = "C:\\app"`},
		`win_copy: {dest: 'C:\app\x.txt', content: hello}`:             {"windows_file {", `path    = "C:\\app\\x.txt"`, `content = "hello"`},
		`win_acl: {path: 'C:\app', user: 'BUILTIN\Users', rights: 'Read,Write', type: allow, state: present, inherit: 'ContainerInherit, ObjectInherit', propagation: None}`: {
			"windows_acl {", "entry {", `principal   = "BUILTIN\\Users"`, `rights      = ["Read", "Write"]`, `inheritance = "container,object"`,
		},
		`win_acl: {path: 'C:\x', user: Guests, rights: Write, type: deny}`:                      {`type      = "deny"`},
		`win_acl_inheritance: {path: 'C:\app', state: present}`:                                 {"windows_acl {", "inherit = true"},
		`win_acl_inheritance: {path: 'C:\app', state: absent, reorganize: true}`:                {"inherit = false"},
		`win_regedit: {path: 'HKLM:\SOFTWARE\App', name: Port, data: 8080, type: dword}`:        {"windows_registry_value {", `key  = "HKLM\\SOFTWARE\\App"`, `type = "dword"`, `data = "8080"`},
		`win_regedit: {path: 'HKLM:\SOFTWARE\App', name: L, type: multistring, data: [a, b]}`:   {`type = "multi_string"`, `data = "a\nb"`},
		`win_regedit: {path: 'HKLM:\SOFTWARE\App', name: E, type: expandstring, data: '%X%\y'}`: {`type = "expand_string"`},
		`win_service: {name: W3SVC, start_mode: auto, state: started}`:                          {"windows_service {", `start_mode = "auto"`, `state      = "running"`},
		`win_feature: {name: Web-Server, include_management_tools: true}`:                       {"windows_feature {", "include_management_tools = true"},
		`win_feature: {name: FS-SMB1, state: absent}`:                                           {`state = "absent"`},
		`win_feature: {name: Web-Server, restart: true}`:                                        {"windows_feature {", "windows_reboot {", "only_if_pending = true"},
		`win_shell: {cmd: 'Get-Date > C:\x', creates: 'C:\x'}`:                                  {"windows_powershell {", "Review:", `creates = "C:\\x"`},
		`win_command: {cmd: 'msiexec /i x', removes: 'C:\y'}`:                                   {"windows_powershell {", "Review:"},
		`win_powershell: {script: 'Write-Output 1', creates: 'C:\x'}`:                           {"windows_powershell {", "Review:"},
		`win_wait_for: {port: 8080, timeout: 60}`:                                               {"windows_wait_for {", "port    = 8080", `timeout = "60s"`},
		`win_package: {product_id: '{23170f69-40c1-2702-2409-000001000000}', state: absent}`:    {"windows_package {", `product_code = "{23170F69-40C1-2702-2409-000001000000}"`, `state        = "absent"`},
		`ansible.windows.win_wait_for: {path: 'C:\ready'}`:                                      {"windows_wait_for {"},
		`win_user: {name: appsvc, fullname: App, description: Runs it, account_disabled: no}`:   {"windows_user {", `full_name   = "App"`, "disabled    = false"},
		`win_group: {name: AppAdmins, description: Admins}`:                                     {"windows_group {", `description = "Admins"`},
		`community.windows.win_scheduled_task: {name: Nightly, username: SYSTEM, run_level: highest, actions: [{path: 'C:\Windows\System32\cmd.exe', arguments: '/c echo hi'}], triggers: [{type: daily, start_boundary: '2026-01-01T03:00:00', days_interval: 2}, {type: boot}]}`: {
			"windows_scheduled_task {", `execute           = "C:\\Windows\\System32\\cmd.exe"`, `arguments         = "/c echo hi"`, `user              = "SYSTEM"`, `run_level         = "highest"`, "allow_interpreter = true", "runs an interpreter", "trigger {", `type          = "daily"`, `at            = "2026-01-01T03:00:00"`, "days_interval = 2", `type = "boot"`,
		},
		`community.windows.win_iis_webapppool: {name: shop, state: started, attributes: {managedRuntimeVersion: '', managedPipelineMode: Classic, processModel.identityType: NetworkService}}`: {
			"windows_iis_app_pool {", `name                    = "shop"`, `managed_runtime_version = ""`, `pipeline_mode           = "classic"`, `identity                = "NetworkService"`,
		},
		`microsoft.iis.web_app_pool: {name: shop, state: stopped}`: {"windows_iis_app_pool {", `state = "stopped"`},
		`win_iis_website: {name: shop, physical_path: 'C:\sites\shop', application_pool: shop, port: 8080, ip: 10.0.0.4, hostname: shop.example.com}`: {
			"windows_iis_site {", `physical_path = "C:\\sites\\shop"`, `app_pool      = "shop"`, "binding {", "port        = 8080", `ip          = "10.0.0.4"`, `host_header = "shop.example.com"`, "TODO(convert): Ansible used port, ip and hostname only when it made the site", "anyone but administrators can change",
		},
		`microsoft.iis.website: {name: shop, physical_path: 'C:\sites\shop', state: stopped, bindings: {set: [{port: 80, hostname: a.example.com}, {port: 81, protocol: http}]}}`: {
			"windows_iis_site {", `state         = "stopped"`, `host_header = "a.example.com"`, "port = 81",
		},
		`win_group_membership: {name: Administrators, members: [appsvc, 'LAB\ops'], state: pure}`: {
			"windows_group {", `members       = ["appsvc", "LAB\\ops"]`, "authoritative = true",
		},
		`community.windows.win_firewall_rule: {name: HTTPS in, localport: 443, protocol: tcp, action: allow, direction: in, state: present, enabled: yes}`: {
			"windows_firewall_rule {", `name        = "HTTPS in"`, `local_ports = ["443"]`, `protocol    = "tcp"`, "enabled     = true",
		},
		`microsoft.ad.domain: {dns_domain_name: lab.example.com, domain_netbios_name: LAB, safe_mode_password: '{{ dsrm }}', database_path: 'F:\NTDS', reboot: true, reboot_timeout: 900}`: {
			"windows_ad_forest {", `domain_name   = "lab.example.com"`, `netbios_name  = "LAB"`, `database_path = "F:\\NTDS"`, "TODO(convert): Set safe_mode_password_wo",
			"windows_reboot {", `timeout         = "900s"`, "windows_wait_for {", "port = 9389",
		},
		`ansible.windows.win_domain: {dns_domain_name: lab.example.com, safe_mode_password: x}`: {"windows_ad_forest {"},
		`microsoft.ad.domain_child: {dns_domain_name: emea.lab.example.com, domain_admin_user: 'lab.example.com\admin', domain_admin_password: x, safe_mode_password: x, domain_type: child, log_path: 'E:\Logs'}`: {
			"windows_ad_domain {", `domain_name = "emea.lab.example.com"`, `username    = "lab.example.com\\admin"`, `log_path    = "E:\\Logs"`, "TODO(convert): Set password_wo and safe_mode_password_wo",
		},
		`win_dns_client: {adapter_names: Ethernet, dns_servers: [10.0.0.4, 10.0.0.5]}`: {"windows_dns_client {", `interface = "Ethernet"`, `servers   = ["10.0.0.4", "10.0.0.5"]`},
		`win_firewall_rule: {name: SQL, localport: '1433,1434', remoteip: '10.0.0.0/8', protocol: tcp, profiles: [Domain, Private], direction: out, action: block}`: {
			`local_ports      = ["1433", "1434"]`, `remote_addresses = ["10.0.0.0/8"]`, `profiles         = ["domain", "private"]`, `direction        = "outbound"`, `action           = "block"`,
		},
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
}

func TestWindowsLeftForAPerson(t *testing.T) {
	for reason, task := range map[string]string{
		"runs on every play":           `win_shell: Restart-Computer`,
		"creates is a glob":            `win_command: {cmd: x, creates: 'C:\*.done'}`,
		"sets executable":              `win_shell: {cmd: x, creates: 'C:\x', executable: cmd}`,
		"reboots on every play":        `win_reboot: {}`,
		"removes a path":               `win_file: {path: 'C:\x', state: absent}`,
		"only checks or touches":       `win_file: {path: 'C:\x', state: touch}`,
		"into a folder":                `win_copy: {src: a, dest: 'C:\dir\'}`,
		"remote_src":                   `win_copy: {src: 'C:\a', dest: 'C:\b', remote_src: true}`,
		"force: no":                    `win_copy: {dest: 'C:\b', content: x, force: no}`,
		"Jinja template":               `win_template: {src: a.j2, dest: 'C:\b'}`,
		"the right":                    `win_acl: {path: 'C:\x', user: u, rights: 'Synchronize', type: allow}`,
		"sets propagation":             `win_acl: {path: 'C:\x', user: u, rights: Read, type: allow, propagation: InheritOnly}`,
		"state \"absent\"":             `win_acl: {path: 'C:\x', user: u, rights: Read, type: allow, state: absent}`,
		"removes inherited":            `win_acl_inheritance: {path: 'C:\x', state: absent}`,
		"isn't under HKLM":             `win_regedit: {path: 'HKCU:\Software\x', name: a, data: b}`,
		"binary data":                  `win_regedit: {path: 'HKLM:\x', name: a, data: 'hex:00', type: binary}`,
		"isn't a decimal":              `win_regedit: {path: 'HKLM:\x', name: a, data: 0xff, type: dword}`,
		"needs data":                   `win_regedit: {path: 'HKLM:\x'}`,
		"state \"restarted\"":          `win_service: {name: x, state: restarted}`,
		"sets username":                `win_service: {name: x, state: started, username: u}`,
		"several features":             `win_feature: {name: [a, b]}`,
		"no SHA-256":                   `win_package: {path: 'https://e/a.msi', product_id: '{23170F69-40C1-2702-2409-000001000000}'}`,
		"removes by product_code":      `win_package: {path: 'C:\a.msi', state: absent}`,
		"removes a user":               `win_user: {name: a, state: absent}`,
		"sets groups":                  `win_user: {name: a, groups: [Users]}`,
		"removes a group":              `win_group: {name: a, state: absent}`,
		"takes members out":            `win_group_membership: {name: a, members: [b], state: absent}`,
		"removes a rule":               `win_firewall_rule: {name: a, state: absent}`,
		"removes it":                   `win_iis_webapppool: {name: a, state: absent}`,
		"restarts it":                  `microsoft.iis.web_app_pool: {name: a, state: restarted}`,
		"attribute autoStart":          `win_iis_webapppool: {name: a, attributes: {autoStart: false}}`,
		"processModel.userName":        `web_app_pool: {name: a, attributes: {processModel.userName: x}}`,
		"has no port":                  `win_iis_website: {name: a, physical_path: 'C:\x'}`,
		"site_id":                      `win_iis_website: {name: a, physical_path: 'C:\x', port: 80, site_id: 5}`,
		"https binding":                `website: {name: a, physical_path: 'C:\x', bindings: {set: [{port: 443, protocol: https}]}}`,
		"bindings.set":                 `website: {name: a, physical_path: 'C:\x', bindings: {add: [{port: 80}]}}`,
		"can't take":                   `win_firewall_rule: {name: 'a*b', localport: 80, protocol: tcp}`,
		"sets program":                 `win_firewall_rule: {name: a, program: 'C:\x.exe'}`,
		"without DNS":                  `microsoft.ad.domain: {dns_domain_name: lab.test, safe_mode_password: x, install_dns: false}`,
		"sets forest_mode":             `microsoft.ad.domain: {dns_domain_name: lab.test, safe_mode_password: x, forest_mode: WinThreshold}`,
		"not a new tree":               `microsoft.ad.domain_child: {dns_domain_name: corp.test, domain_type: tree, domain_admin_user: a@lab.test}`,
		"makes the domain without DNS": `microsoft.ad.domain_child: {dns_domain_name: emea.lab.test, domain_admin_user: a@lab.test, install_dns: false}`,
		"sets site_name":               `microsoft.ad.domain_child: {dns_domain_name: emea.lab.test, domain_admin_user: a@lab.test, site_name: s}`,
		"has no domain_admin_user":     `microsoft.ad.domain_child: {dns_domain_name: emea.lab.test}`,
		"its domain's DNS name":        `microsoft.ad.domain_child: {dns_domain_name: emea.lab.test, domain_admin_user: 'LAB\admin'}`,
		"all of them":                  `win_dns_client: {adapter_names: '*', dns_servers: [10.0.0.4]}`,
		"resets DNS to DHCP":           `win_dns_client: {adapter_names: Ethernet, dns_servers: []}`,
		"the domain module":            `community.example.domain: {dns_domain_name: lab.test}`,
		"uses the domain module":       `domain: {dns_domain_name: lab.test}`,
		"win_chocolatey module":        `win_chocolatey: {name: git}`,
		"win_dsc module":               `win_dsc: {resource_name: x}`,
		"removes a task":               `win_scheduled_task: {name: a, state: absent}`,
		"other than one action":        `win_scheduled_task: {name: a, username: SYSTEM, actions: [{path: 'C:\a.exe'}, {path: 'C:\b.exe'}]}`,
		"without its full path":        `win_scheduled_task: {name: a, username: SYSTEM, actions: [{path: cmd.exe}]}`,
		"doesn't name the user":        `win_scheduled_task: {name: a, actions: [{path: 'C:\a.exe'}]}`,
		"which Conn3x has no setting":  `win_scheduled_task: {name: a, username: SYSTEM, actions: [{path: 'C:\a.exe'}], triggers: [{type: boot, delay: PT1M}]}`,
		"trigger, which":               `win_scheduled_task: {name: a, username: SYSTEM, actions: [{path: 'C:\a.exe'}], triggers: [{type: idle}]}`,
		"plain local time":             `win_scheduled_task: {name: a, username: SYSTEM, actions: [{path: 'C:\a.exe'}], triggers: [{type: daily, start_boundary: '2026-01-01T03:00:00+01:00'}]}`,
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}

// A password is never copied: the step gets a note to wire one in instead.
func TestWinUserPasswordNotCopied(t *testing.T) {
	const secret = "s3ntinel-convert-pw"
	res := convertString(t, "- hosts: all\n  tasks:\n    - win_user: {name: appsvc, password: "+secret+", update_password: on_create}\n")
	if res.Converted != 1 || strings.Contains(string(res.HCL), secret) || !strings.Contains(string(res.HCL), "password_wo") {
		t.Errorf("converted %d, review %+v:\n%s", res.Converted, res.Review, res.HCL)
	}
}

// A task's password is never copied: the step gets a note instead.
func TestWinScheduledTaskPasswordNotCopied(t *testing.T) {
	const secret = "s3ntinel-task-pw"
	res := convertString(t, "- hosts: all\n  tasks:\n    - win_scheduled_task: {name: a, username: 'LAB\\svc', password: "+secret+", logon_type: password, actions: [{path: 'C:\\a.exe'}]}\n")
	if res.Converted != 1 || strings.Contains(string(res.HCL), secret) || !strings.Contains(string(res.HCL), "password_wo") {
		t.Errorf("converted %d, review %+v:\n%s", res.Converted, res.Review, res.HCL)
	}
}

// A task left for a person is echoed into the file, so its secrets are left
// out of the echo, wherever they sit.
func TestRefusedTasksDontEchoSecrets(t *testing.T) {
	const secret = "s3ntinel-Dsrm-9Q"
	for _, task := range []string{
		`microsoft.ad.domain: {dns_domain_name: lab.test, safe_mode_password: ` + secret + `, install_dns: false}`,
		`microsoft.ad.domain: {dns_domain_name: lab.test, safe_mode_password: ` + secret + `, forest_mode: WinThreshold}`,
		`microsoft.ad.domain: {dns_domain_name: lab.test, safe_mode_password: ` + secret + `, reboot: true, reboot_timeout: soon}`,
		`microsoft.ad.domain: {dns_domain_name: lab.test, safe_mode_password: ` + secret + `, reboot: true, reboot_timeout: 0}`,
		`microsoft.ad.domain: {dns_domain_name: lab.test, safe_mode_password: ` + secret + `, some_new_option: x}`,
		`win_domain: {dns_domain_name: lab.test, safe_mode_password: ` + secret + `, install_dns: no}`,
		`microsoft.ad.domain: {dns_domain_name: lab.test, dns_delegation_credential: {username: a, password: ` + secret + `}}`,
		`microsoft.ad.user: {name: alice, password: ` + secret + `, groups: {add: [ops]}}`,
		`microsoft.ad.user: {name: alice, password: ` + secret + `, state: absent}`,
		`microsoft.ad.user: {name: alice, password: ` + secret + `, domain_username: a, domain_password: ` + secret + `}`,
		`microsoft.ad.user: {name: alice, password: ` + secret + `, password_expired: true}`,
		`microsoft.ad.user: {name: alice, sam_account_name: bob, password: ` + secret + `}`,
		`community.windows.win_domain_user: {name: alice, password: ` + secret + `, state: query}`,
		`win_domain_user: name=alice password=` + secret + ` groups=ops`,
		`microsoft.ad.group: {name: g, scope: global, domain_credentials: [{username: a, password: ` + secret + `}]}`,
		`microsoft.ad.group: {name: g, members: {remove: [a]}, domain_password: ` + secret + `}`,
		`microsoft.ad.group: {name: g, members: {add: ['LAB\a']}, domain_password: ` + secret + `}`,
		`microsoft.ad.ou: {name: x, domain_password: ` + secret + `}`,
		`microsoft.ad.ou: {name: x, identity: y, api_token: ` + secret + `}`,
		`community.windows.win_domain_group: {name: g, scope: global, domain_password: ` + secret + `, ignore_protection: true}`,
		`community.windows.win_domain_user: {name: alice, Password: ` + secret + `, api_token: ` + secret + `x}`,
		"microsoft.ad.domain:\n        dns_domain_name: lab.test\n        install_dns: false\n      args:\n        safe_mode_password: " + secret,
		`microsoft.ad.domain: dns_domain_name=lab.test safe_mode_password=` + secret + ` install_dns=false`,
		`win_user: name=bob password="` + secret + ` with spaces" groups=x unknown_opt=1`,
		`win_user: name=bob password='` + secret + `' groups=x`,
		`microsoft.ad.membership: {dns_domain_name: lab.test, domain_admin_user: a, domain_admin_password: ` + secret + `, state: workgroup}`,
		`microsoft.ad.membership: {dns_domain_name: lab.test, domain_admin_user: a, domain_admin_password: ` + secret + `, state: domain, hostname: x}`,
		`win_domain_membership: dns_domain_name=lab.test domain_admin_user=a domain_admin_password=` + secret + ` state=domain offline_join_blob=b`,
		`microsoft.ad.domain_child: {dns_domain_name: emea.lab.test, domain_admin_user: a@lab.test, domain_admin_password: ` + secret + `, safe_mode_password: ` + secret + `, domain_mode: WinThreshold}`,
		`microsoft.ad.domain_child: {dns_domain_name: emea.lab.test, domain_admin_user: 'LAB\a', domain_admin_password: ` + secret + `, safe_mode_password: ` + secret + `}`,
		`microsoft.ad.domain_controller: {dns_domain_name: lab.test, domain_admin_user: a, domain_admin_password: ` + secret + `, safe_mode_password: ` + secret + `, state: member_server, local_admin_password: ` + secret + `}`,
		`microsoft.ad.domain_controller: {dns_domain_name: lab.test, domain_admin_user: a, domain_admin_password: ` + secret + `, safe_mode_password: ` + secret + `, state: domain_controller, read_only: true}`,
		`win_domain_controller: {dns_domain_name: lab.test, domain_admin_user: a, domain_admin_password: ` + secret + `, safe_mode_password: ` + secret + `, state: domain_controller, site_name: s}`,
		`microsoft.ad.domain_controller: {dns_domain_name: lab.test, domain_admin_password: ` + secret + `, safe_mode_password: ` + secret + `, state: domain_controller}`,
		`microsoft.ad.membership: {dns_domain_name: lab.test, domain_admin_user: a, domain_admin_password: ` + secret + `, state: domain, domain_server: ds.lab.test}`,
		`microsoft.ad.membership: {dns_domain_name: lab.test, domain_admin_password: ` + secret + `, state: domain}`,
		`microsoft.ad.domain_controller: {dns_domain_name: lab.test, domain_admin_user: a, domain_admin_password: ` + secret + `, safe_mode_password: ` + secret + `, state: domain_controller, install_dns: false}`,
		`win_domain_controller: {dns_domain_name: lab.test, domain_admin_user: a, domain_admin_password: ` + secret + `, safe_mode_password: ` + secret + `, state: domain_controller, install_media_path: 'C:\InstallMedia'}`,
		`microsoft.ad.domain_controller: {dns_domain_name: lab.test, domain_admin_user: a, domain_admin_password: ` + secret + `, safe_mode_password: ` + secret + `, state: domain_controller, replication_source_dc: dc1.lab.test}`,
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if len(res.Review) != 1 || strings.Contains(string(res.HCL), secret) || !strings.Contains(string(res.HCL), "secret left out") {
			t.Errorf("%s: review %+v\n%s", task, res.Review, res.HCL)
		}
	}
}

// A group's members are checked after domain_password, so these carry no
// password: with one, the task would stop at that and never reach them.
func TestADGroupRefusalReasons(t *testing.T) {
	for task, reason := range map[string]string{
		`microsoft.ad.group: {name: g, scope: global, members: [alice]}`:                                   "gives members that aren't add, set or remove lists",
		`microsoft.ad.group: {name: g, scope: global, members: {add: [a], set: [b]}}`:                      "both adds and sets members",
		`microsoft.ad.group: {name: g, scope: global, members: {add: [a], lookup_failure_action: warn}}`:   "sets lookup_failure_action warn",
		`win_domain_group: {name: g, scope: global, members: {add: [a], something_new: x}}`:                "sets something_new in members",
		`microsoft.ad.group: {name: g, scope: global, members: {add: ['CN=alice,OU=Lab,DC=lab,DC=test']}}`: "something other than its sAMAccountName",
		`win_domain_group: {name: g, scope: global, members: {add: [alice@lab.test]}}`:                     "something other than its sAMAccountName",
		`microsoft.ad.group: {name: g, scope: global, members: {add: ['LAB\a']}}`:                          "something other than its sAMAccountName",
		`microsoft.ad.group: {name: g, scope: global, members: {remove: [a]}}`:                             "takes members out by name",
		`microsoft.ad.group: {name: g, scope: global, domain_server: dc1}`:                                 "sets domain_server",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, reason)
		}
	}
}

// An anchor could carry a secret's value to the place it's defined, which the
// redaction doesn't see, so a task with any is echoed not at all.
func TestRefusedTasksWithAnchorsAreNotEchoed(t *testing.T) {
	const secret = "s3ntinel-Anchor-9Q"
	task := `microsoft.ad.domain: {dns_domain_name: lab.test, x: &p ` + secret + `, safe_mode_password: *p, install_dns: false}`
	res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
	if len(res.Review) != 1 || strings.Contains(string(res.HCL), secret) || !strings.Contains(string(res.HCL), "anchors or aliases") {
		t.Errorf("review %+v\n%s", res.Review, res.HCL)
	}
}

// Only the microsoft.ad modules listed by full name convert; the rest aren't
// the Linux modules that share their last name.
func TestMicrosoftADOnlyByFullName(t *testing.T) {
	for _, task := range []string{`microsoft.ad.computer: {name: web1}`, `microsoft.ad.object: {name: x, type: contact}`} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "microsoft.ad.") {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}

func TestWindowsADObjects(t *testing.T) {
	for task, wants := range map[string][]string{
		`microsoft.ad.ou: {name: Lab, path: 'DC=lab,DC=example,DC=com', description: Lab OU, protect_from_deletion: false}`: {
			"windows_ad_ou {", `name        = "Lab"`, `path        = "DC=lab,DC=example,DC=com"`, "protected   = false",
		},
		`microsoft.ad.ou: {name: Lab, path: microsoft.ad.default_path}`: {"windows_ad_ou {", `name = "Lab"`},
		`microsoft.ad.group: {name: AppAdmins, scope: Global, category: security, path: 'OU=Lab,DC=lab,DC=example,DC=com', members: {set: [alice, 'web1$']}}`: {
			"windows_ad_group {", `scope         = "global"`, `members       = ["alice", "web1$"]`, "authoritative = true",
		},
		`microsoft.ad.group: {name: Ops, scope: universal, members: {add: [bob]}}`: {"windows_ad_group {", `members = ["bob"]`},
		`microsoft.ad.group: {name: Empty, scope: global, members: {set: []}}`:     {"windows_ad_group {", `members       = []`, "authoritative = true"},
		`community.windows.win_domain_group: {name: Ops, scope: domainlocal, organizational_unit: 'OU=Lab,DC=lab,DC=example,DC=com'}`: {
			"windows_ad_group {", `path  = "OU=Lab,DC=lab,DC=example,DC=com"`, `scope = "domainlocal"`,
		},
		`microsoft.ad.user: {name: alice, sam_account_name: alice, upn: alice@lab.example.com, firstname: Alice, surname: Smith, password: '{{ pw }}', update_password: on_create, password_never_expires: true, enabled: true}`: {
			"windows_ad_user {", `given_name             = "Alice"`, "password_never_expires = true", "enabled                = true", "TODO(convert): Set password_wo",
		},
		`community.windows.win_domain_user: {name: bob, lastname: Jones, path: 'OU=Lab,DC=lab,DC=example,DC=com', state: present}`: {
			"windows_ad_user {", `surname = "Jones"`,
		},
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
		if strings.Contains(string(res.HCL), "{{ pw }}") {
			t.Errorf("%s: the password variable is in the output", task)
		}
	}
}

func TestWindowsJoinAndDC(t *testing.T) {
	for task, wants := range map[string][]string{
		`microsoft.ad.membership: {dns_domain_name: lab.example.com, domain_admin_user: 'LAB\joiner', domain_admin_password: '{{ pw }}', domain_ou_path: 'OU=Servers,DC=lab,DC=example,DC=com', state: domain, reboot: true}`: {
			"windows_domain_membership {", `domain   = "lab.example.com"`, `username = "LAB\\joiner"`, `ou       = "OU=Servers,DC=lab,DC=example,DC=com"`, "TODO(convert): Set password_wo",
			"windows_reboot {", "only_if_pending = true",
		},
		`ansible.windows.win_domain_membership: {dns_domain_name: lab.example.com, domain_admin_user: joiner@lab.example.com, domain_admin_password: x, state: domain}`: {
			"windows_domain_membership {", `username = "joiner@lab.example.com"`,
		},
		`microsoft.ad.domain_controller: {dns_domain_name: lab.example.com, domain_admin_user: 'LAB\admin', domain_admin_password: x, safe_mode_password: y, state: domain_controller, database_path: 'F:\NTDS', domain_log_path: 'F:\NTDSLOG', reboot: true, reboot_timeout: 900}`: {
			"windows_ad_domain_controller {", `domain_name   = "lab.example.com"`, `log_path      = "F:\\NTDSLOG"`, "TODO(convert): Set password_wo and safe_mode_password_wo",
			`timeout         = "900s"`, "windows_wait_for {", "port = 9389",
		},
		`win_domain_controller: {dns_domain_name: lab.example.com, domain_admin_user: 'LAB\admin', domain_admin_password: x, safe_mode_password: y, state: domain_controller, install_dns: true}`: {
			"windows_ad_domain_controller {",
		},
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
		for _, secret := range []string{"{{ pw }}", "x\"", "y\""} {
			if strings.Contains(string(res.HCL), secret) {
				t.Errorf("%s: output has %q:\n%s", task, secret, res.HCL)
			}
		}
	}
}

// win_updates converts as far as windows_update means the same: its
// categories matched the way win_updates.ps1 matches them, Ansible's default
// of three written out, KB-only lists, and reboot as a windows_reboot step
// with Ansible's 1200 seconds unless the task says otherwise.
func TestWinUpdates(t *testing.T) {
	flat := func(b []byte) string { return strings.Join(strings.Fields(string(b)), " ") }
	for task, wants := range map[string][]string{
		`ansible.windows.win_updates: {}`: {
			"windows_update {", `categories = ["CriticalUpdates", "SecurityUpdates", "UpdateRollups"]`,
		},
		`win_updates: {category_names: [Security Updates, securityupdates, 'critical updates', Drivers]}`: {
			`categories = ["SecurityUpdates", "CriticalUpdates", "Drivers"]`,
		},
		`win_updates: {category_names: '*'}`: {
			`categories = ["Applications", "Connectors", "CriticalUpdates", "DefinitionUpdates", "DeveloperKits", "Drivers", "FeaturePacks", "Guidance", "SecurityUpdates", "ServicePacks", "Tools", "UpdateRollups", "Updates", "Upgrades"]`,
		},
		`win_updates: {category_names: SecurityUpdates, accept_list: [KB5034441, kb5034439], reject_list: [KB5034122]}`: {
			`accept_list = ["KB5034441", "KB5034439"]`, `reject_list = ["KB5034122"]`,
		},
		`win_updates: {category_names: [SecurityUpdates], reboot: true}`: {
			"windows_update {", "windows_reboot {", "only_if_pending = true", `timeout = "1200s"`,
			"Ansible installed, rebooted and searched again until nothing was left",
		},
		`win_updates: {reboot: true, reboot_timeout: 3600, server_selection: default}`: {`timeout = "3600s"`},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
			continue
		}
		for _, w := range wants {
			if !strings.Contains(flat(res.HCL), w) {
				t.Errorf("%s: output lacks %q:\n%s", task, w, res.HCL)
			}
		}
	}

	// The note goes on the windows_update step, where a reader looks for
	// what gets installed, not on the reboot.
	res := convertString(t, "- hosts: all\n  tasks:\n    - win_updates: {reboot: true}\n")
	hcl := string(res.HCL)
	if note, upd, reboot := strings.Index(hcl, "searched again"), strings.Index(hcl, "windows_update {"), strings.Index(hcl, "windows_reboot {"); note < 0 || note > upd || upd > reboot {
		t.Errorf("the note should come before the windows_update step, which comes before the reboot:\n%s", hcl)
	}

	res = convertString(t, "- hosts: all\n  tasks:\n    - win_updates: {state: searched, category_names: '*'}\n")
	if len(res.Review) != 0 || strings.Contains(string(res.HCL), "windows_update {") || !strings.Contains(string(res.HCL), "state searched only lists updates") {
		t.Errorf("state searched should be left out with a note: review %+v\n%s", res.Review, res.HCL)
	}

	for reason, task := range map[string]string{
		"only downloads updates":                           `win_updates: {state: downloaded}`,
		"names the category \"Application\"":               `win_updates: {category_names: [Application]}`,
		"also matches products":                            `win_updates: {category_names: [Windows Server 2019]}`,
		"takes titles and patterns there too":              `win_updates: {accept_list: ['Cumulative Update']}`,
		"has server_selection windows_update":              `win_updates: {server_selection: windows_update}`,
		"writes Windows Update's log":                      `win_updates: {log_path: 'C:\wu.txt'}`,
		"sets skip_optional":                               `win_updates: {skip_optional: true}`,
		"sets both reject_list and its old name blacklist": `win_updates: {reject_list: [KB5034441], blacklist: [KB5034439]}`,
		"retries updates that didn't take":                 `win_updates: {reboot: true, maximum_retries_on_failed_updates: 3}`,
		"reboot_timeout that isn't a positive":             `win_updates: {reboot: true, reboot_timeout: soon}`,
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}
