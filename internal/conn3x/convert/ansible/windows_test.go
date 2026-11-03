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
		"runs on every play":          `win_shell: Restart-Computer`,
		"creates is a glob":           `win_command: {cmd: x, creates: 'C:\*.done'}`,
		"sets executable":             `win_shell: {cmd: x, creates: 'C:\x', executable: cmd}`,
		"reboots on every play":       `win_reboot: {}`,
		"removes a path":              `win_file: {path: 'C:\x', state: absent}`,
		"only checks or touches":      `win_file: {path: 'C:\x', state: touch}`,
		"into a folder":               `win_copy: {src: a, dest: 'C:\dir\'}`,
		"remote_src":                  `win_copy: {src: 'C:\a', dest: 'C:\b', remote_src: true}`,
		"force: no":                   `win_copy: {dest: 'C:\b', content: x, force: no}`,
		"Jinja template":              `win_template: {src: a.j2, dest: 'C:\b'}`,
		"the right":                   `win_acl: {path: 'C:\x', user: u, rights: 'Synchronize', type: allow}`,
		"sets propagation":            `win_acl: {path: 'C:\x', user: u, rights: Read, type: allow, propagation: InheritOnly}`,
		"state \"absent\"":            `win_acl: {path: 'C:\x', user: u, rights: Read, type: allow, state: absent}`,
		"removes inherited":           `win_acl_inheritance: {path: 'C:\x', state: absent}`,
		"isn't under HKLM":            `win_regedit: {path: 'HKCU:\Software\x', name: a, data: b}`,
		"binary data":                 `win_regedit: {path: 'HKLM:\x', name: a, data: 'hex:00', type: binary}`,
		"isn't a decimal":             `win_regedit: {path: 'HKLM:\x', name: a, data: 0xff, type: dword}`,
		"needs data":                  `win_regedit: {path: 'HKLM:\x'}`,
		"state \"restarted\"":         `win_service: {name: x, state: restarted}`,
		"sets username":               `win_service: {name: x, state: started, username: u}`,
		"several features":            `win_feature: {name: [a, b]}`,
		"no SHA-256":                  `win_package: {path: 'https://e/a.msi', product_id: '{23170F69-40C1-2702-2409-000001000000}'}`,
		"removes by product_code":     `win_package: {path: 'C:\a.msi', state: absent}`,
		"removes a user":              `win_user: {name: a, state: absent}`,
		"sets groups":                 `win_user: {name: a, groups: [Users]}`,
		"removes a group":             `win_group: {name: a, state: absent}`,
		"takes members out":           `win_group_membership: {name: a, members: [b], state: absent}`,
		"removes a rule":              `win_firewall_rule: {name: a, state: absent}`,
		"removes it":                  `win_iis_webapppool: {name: a, state: absent}`,
		"restarts it":                 `microsoft.iis.web_app_pool: {name: a, state: restarted}`,
		"attribute autoStart":         `win_iis_webapppool: {name: a, attributes: {autoStart: false}}`,
		"processModel.userName":       `web_app_pool: {name: a, attributes: {processModel.userName: x}}`,
		"has no port":                 `win_iis_website: {name: a, physical_path: 'C:\x'}`,
		"site_id":                     `win_iis_website: {name: a, physical_path: 'C:\x', port: 80, site_id: 5}`,
		"https binding":               `website: {name: a, physical_path: 'C:\x', bindings: {set: [{port: 443, protocol: https}]}}`,
		"bindings.set":                `website: {name: a, physical_path: 'C:\x', bindings: {add: [{port: 80}]}}`,
		"can't take":                  `win_firewall_rule: {name: 'a*b', localport: 80, protocol: tcp}`,
		"sets program":                `win_firewall_rule: {name: a, program: 'C:\x.exe'}`,
		"win_updates module":          `win_updates: {category_names: [SecurityUpdates]}`,
		"win_chocolatey module":       `win_chocolatey: {name: git}`,
		"win_dsc module":              `win_dsc: {resource_name: x}`,
		"removes a task":              `win_scheduled_task: {name: a, state: absent}`,
		"other than one action":       `win_scheduled_task: {name: a, username: SYSTEM, actions: [{path: 'C:\a.exe'}, {path: 'C:\b.exe'}]}`,
		"without its full path":       `win_scheduled_task: {name: a, username: SYSTEM, actions: [{path: cmd.exe}]}`,
		"doesn't name the user":       `win_scheduled_task: {name: a, actions: [{path: 'C:\a.exe'}]}`,
		"which Conn3x has no setting": `win_scheduled_task: {name: a, username: SYSTEM, actions: [{path: 'C:\a.exe'}], triggers: [{type: boot, delay: PT1M}]}`,
		"trigger, which":              `win_scheduled_task: {name: a, username: SYSTEM, actions: [{path: 'C:\a.exe'}], triggers: [{type: idle}]}`,
		"plain local time":            `win_scheduled_task: {name: a, username: SYSTEM, actions: [{path: 'C:\a.exe'}], triggers: [{type: daily, start_boundary: '2026-01-01T03:00:00+01:00'}]}`,
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
