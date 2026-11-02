// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"
)

// reviewScript is on every windows_powershell step made from a task: a script
// converted without running it is worth a person's look.
const reviewScript = "Review: this runs as PowerShell through windows_powershell. Check it does what the task did, and pass values through args."

// windowsGuards copies creates and removes, refusing a glob, since a step tests
// the path as written.
func (in *input) windowsGuards(attrs []attr) ([]attr, string) {
	for _, k := range []string{"creates", "removes"} {
		if strings.ContainsAny(in.str(k), "*?[") {
			return nil, k + " is a glob pattern; Conn3x tests the path as written"
		}
		attrs = in.optional(attrs, k, k)
	}
	return attrs, ""
}

func winScriptModule(in *input, script string) ([]step, string) {
	if script == "" {
		return nil, "has no script or command"
	}
	attrs, reason := in.windowsGuards([]attr{s("script", script)})
	if reason != "" {
		return nil, reason
	}
	if !in.has("creates") && !in.has("removes") {
		return nil, "runs on every play; give it a creates, removes or unless guard, or triggers, so Conn3x knows when it's done"
	}
	return one("windows_powershell", attrs, reviewScript)
}

func rawOrCmd(in *input) string {
	if n, ok := in.args["_raw"]; ok {
		return in.render("command", n.Value)
	}
	return in.str("cmd")
}

// A win_shell runs PowerShell by default, which is what a step runs.
func winShellModule(in *input) ([]step, string) {
	if in.has("executable") {
		return nil, "sets executable; windows_powershell runs PowerShell only"
	}
	return winScriptModule(in, rawOrCmd(in))
}

// A win_command runs a program with no shell, and PowerShell reads the same
// line by its own rules, so a person needs to check it, and the note says so.
func winCommandModule(in *input) ([]step, string) {
	return winScriptModule(in, rawOrCmd(in))
}

func winPowershellModule(in *input) ([]step, string) {
	return winScriptModule(in, in.str("script"))
}

func winRebootModule(in *input) ([]step, string) {
	in.ignore("reboot_timeout", "msg", "pre_reboot_delay", "post_reboot_delay")
	return nil, "reboots on every play; a Conn3x windows_reboot step reboots once, and again when its triggers change or with only_if_pending, so choose one"
}

func winWaitForModule(in *input) ([]step, string) {
	if h := in.str("host"); h != "" && h != "localhost" && h != "127.0.0.1" {
		return nil, "waits for another host, which the converter can't translate yet"
	}
	in.state("started", "started", "present")
	var attrs []attr
	attrs = in.optional(attrs, "path", "path")
	if in.has("port") {
		attrs = append(attrs, attr{key: "port", raw: in.str("port")})
	}
	if in.has("timeout") {
		secs, err := strconv.Atoi(in.str("timeout"))
		if err != nil {
			return nil, "has a timeout that isn't a number of seconds"
		}
		attrs = append(attrs, s("timeout", fmt.Sprintf("%ds", secs)))
	}
	in.ignore("delay", "sleep")
	return one("windows_wait_for", attrs)
}

func winFileModule(in *input) ([]step, string) {
	path := in.str("path", "dest", "name")
	switch in.state("file", "directory", "file", "absent", "touch") {
	case "directory":
		return one("windows_directory", []attr{s("path", path)})
	case "absent":
		return nil, "removes a path; Conn3x removes a windows_file with on_remove = \"delete\" when its step goes, so there's nothing to convert this to yet"
	}
	return nil, "only checks or touches a file; windows_file needs its content"
}

func winCopyModule(in *input) ([]step, string) {
	dest := in.str("dest")
	if strings.HasSuffix(dest, `\`) || strings.HasSuffix(dest, "/") {
		return nil, "copies into a folder; windows_file needs the file's own path"
	}
	if in.has("remote_src") && in.bool("remote_src", false) {
		return nil, "copies a file already on the host (remote_src), which the converter can't translate yet"
	}
	attrs := []attr{s("path", dest)}
	switch {
	case in.has("content"):
		attrs = append(attrs, s("content", in.str("content")))
	case in.has("src"):
		if p := in.local("files", in.str("src")); p != "" {
			attrs = append(attrs, attr{key: "content", raw: fmt.Sprintf(`file("${path.module}/%s")`, p)})
		}
	default:
		return nil, "has neither content nor src"
	}
	if !in.bool("force", true) {
		return nil, "sets force: no, so Ansible writes the file only when it's missing; Conn3x would replace it on every apply"
	}
	in.ignore("backup")
	return one("windows_file", attrs)
}

func winTemplateModule(in *input) ([]step, string) {
	in.ignore("src", "dest", "backup", "newline_sequence", "force")
	return nil, "is a Jinja template; render it with templatefile() into a windows_file, whose line endings are written as they are, where win_template defaults to CRLF"
}

var winACLRights = map[string]bool{
	"FullControl": true, "Modify": true, "ReadAndExecute": true, "Read": true, "Write": true,
	"Delete": true, "ReadPermissions": true, "ChangePermissions": true, "TakeOwnership": true,
}

func winACLModule(in *input) ([]step, string) {
	if in.loop {
		return nil, "loops, and a rule's entry can't take a loop value; write one windows_acl with an entry for each"
	}
	in.state("present", "present")
	entry := []attr{s("principal", in.str("user"))}
	var rights []cty.Value
	for _, r := range in.list("rights") {
		if !winACLRights[r] {
			return nil, fmt.Sprintf("uses the right %q, which windows_acl doesn't offer yet", r)
		}
		rights = append(rights, cty.StringVal(r))
	}
	if len(rights) == 0 {
		return nil, "lists no rights"
	}
	entry = append(entry, attr{key: "rights", val: cty.ListVal(rights)})
	if t := strings.ToLower(in.str("type")); t != "" && t != "allow" {
		if t != "deny" {
			return nil, fmt.Sprintf("has a type %q that isn't allow or deny", t)
		}
		entry = append(entry, s("type", t))
	}
	if p := in.str("propagation"); p != "" && !strings.EqualFold(p, "None") {
		return nil, "sets propagation; windows_acl has no such setting yet"
	}
	if in.has("inherit") {
		var flags []string
		for _, f := range in.list("inherit") {
			switch strings.ToLower(f) {
			case "containerinherit":
				flags = append(flags, "container")
			case "objectinherit":
				flags = append(flags, "object")
			case "none":
			default:
				return nil, fmt.Sprintf("has an inherit value %q the converter doesn't know", f)
			}
		}
		if len(flags) == 0 {
			flags = []string{"none"}
		}
		entry = append(entry, s("inheritance", strings.Join(flags, ",")))
	}
	return []step{{module: "windows_acl", attrs: []attr{s("path", in.str("path"))}, blocks: []stepBlock{{name: "entry", attrs: entry}}}}, ""
}

func winACLInheritanceModule(in *input) ([]step, string) {
	on := in.state("absent", "present", "absent") == "present"
	if !on && !in.bool("reorganize", false) {
		return nil, "removes inherited rules outright; windows_acl with inherit = false copies them first, so add authoritative = true and list what stays"
	}
	in.ignore("reorganize")
	return one("windows_acl", []attr{s("path", in.str("path")), {key: "inherit", val: cty.BoolVal(on)}})
}

var regedit = map[string]string{
	"string": "string", "expandstring": "expand_string", "multistring": "multi_string",
	"dword": "dword", "qword": "qword", "binary": "binary",
}

func winRegeditModule(in *input) ([]step, string) {
	in.state("present", "present")
	key := in.str("path", "key")
	switch {
	case strings.HasPrefix(strings.ToUpper(key), `HKLM:\`):
		key = `HKLM\` + key[len(`HKLM:\`):]
	case strings.HasPrefix(strings.ToUpper(key), `HKEY_LOCAL_MACHINE:\`):
		key = `HKLM\` + key[len(`HKEY_LOCAL_MACHINE:\`):]
	default:
		return nil, "isn't under HKLM, the only hive windows_registry_value handles"
	}
	typ := strings.ToLower(in.str("type"))
	if typ == "" {
		typ = "string"
	}
	kind, ok := regedit[typ]
	if !ok {
		return nil, fmt.Sprintf("has the type %q, which windows_registry_value doesn't take", typ)
	}
	if !in.has("data") {
		return nil, "only makes a key or an empty value; windows_registry_value needs data"
	}
	var data string
	if n := in.args["data"]; n.Kind == yaml.SequenceNode {
		if kind != "multi_string" {
			return nil, "gives a list as data for a type that holds one value"
		}
		data = strings.Join(in.list("data"), "\n")
	} else {
		data = in.str("data")
	}
	switch kind {
	case "dword", "qword":
		if !digits.MatchString(data) {
			return nil, "has data that isn't a decimal number; convert it by hand"
		}
	case "binary":
		return nil, "has binary data, whose form the converter doesn't read; windows_registry_value takes it as hex"
	}
	attrs := []attr{s("key", key)}
	attrs = in.optional(attrs, "name", "name", "value")
	in.ignore("delete_key", "hive")
	return one("windows_registry_value", append(attrs, s("type", kind), s("data", data)))
}

func winServiceModule(in *input) ([]step, string) {
	attrs := []attr{s("name", in.str("name"))}
	if in.has("start_mode") {
		m := in.str("start_mode")
		switch m {
		case "auto", "delayed", "manual", "disabled":
			attrs = append(attrs, s("start_mode", m))
		default:
			return nil, fmt.Sprintf("has the start_mode %q, which windows_service doesn't take", m)
		}
	}
	if in.has("state") {
		switch st := in.str("state"); st {
		case "started":
			attrs = append(attrs, s("state", "running"))
		case "stopped":
			attrs = append(attrs, s("state", "stopped"))
		default:
			return nil, fmt.Sprintf("has the state %q; windows_service only keeps a service running or stopped", st)
		}
	}
	if len(attrs) == 1 {
		return nil, "sets neither start_mode nor state"
	}
	return one("windows_service", attrs)
}

func winFeatureModule(in *input) ([]step, string) {
	if n := in.args["name"]; n != nil && n.Kind == yaml.SequenceNode {
		return nil, "lists several features; give each its own task or step"
	}
	st := in.state("present", "present", "absent")
	attrs := []attr{s("name", in.str("name"))}
	if st == "absent" {
		attrs = append(attrs, s("state", "absent"))
	}
	for _, f := range []string{"include_sub_features", "include_management_tools"} {
		if in.has(f) && in.bool(f, false) {
			attrs = append(attrs, attr{key: f, val: cty.True})
		}
	}
	feature := step{module: "windows_feature", attrs: attrs, suffix: "feature"}
	// Conn3x modules never reboot, so a task that would have gets its own step.
	if in.bool("restart", false) {
		return []step{feature, {module: "windows_reboot", suffix: "reboot", attrs: []attr{{key: "only_if_pending", val: cty.True}}}}, ""
	}
	return []step{feature}, ""
}

func winUserModule(in *input) ([]step, string) {
	if in.state("present", "present", "absent") == "absent" {
		return nil, "removes a user; Conn3x deletes a windows_user with on_remove = \"delete\" when its step goes, so there's nothing to convert this to yet"
	}
	if in.has("groups") {
		return nil, "sets groups; give each group a windows_group step with this user in its members"
	}
	attrs := []attr{s("name", in.str("name"))}
	attrs = in.optional(attrs, "full_name", "fullname")
	attrs = in.optional(attrs, "description", "description")
	if in.has("account_disabled") {
		attrs = append(attrs, attr{key: "disabled", val: cty.BoolVal(in.bool("account_disabled", false))})
	}
	// Never read, so a password can't end up in the output.
	in.ignore("update_password")
	var notes []string
	if in.has("password") {
		in.ignore("password")
		notes = append(notes, "TODO(convert): Set password_wo from an ephemeral variable. The task's password isn't copied here.")
	}
	return one("windows_user", attrs, notes...)
}

func winGroupModule(in *input) ([]step, string) {
	if in.state("present", "present", "absent") == "absent" {
		return nil, "removes a group; Conn3x deletes a windows_group with on_remove = \"delete\" when its step goes, so there's nothing to convert this to yet"
	}
	return one("windows_group", in.optional([]attr{s("name", in.str("name"))}, "description", "description"))
}

func winGroupMembershipModule(in *input) ([]step, string) {
	st := in.state("present", "present", "pure", "absent")
	if st == "absent" {
		return nil, "takes members out of a group; windows_group adds them, or keeps the complete list with authoritative = true"
	}
	var vals []cty.Value
	for _, m := range in.list("members") {
		vals = append(vals, cty.StringVal(m))
	}
	if len(vals) == 0 {
		return nil, "lists no members"
	}
	attrs := []attr{s("name", in.str("name")), {key: "members", val: cty.ListVal(vals)}}
	if st == "pure" {
		attrs = append(attrs, attr{key: "authoritative", val: cty.True})
	}
	return one("windows_group", attrs)
}

var firewallRuleID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,127}$`)

func winFirewallRuleModule(in *input) ([]step, string) {
	if in.state("present", "present", "absent") == "absent" {
		return nil, "removes a rule; Conn3x deletes a windows_firewall_rule when its step goes, so there's nothing to convert this to yet"
	}
	// Ansible finds a rule by its display name, Conn3x by its ID.
	name := in.str("name")
	if !firewallRuleID.MatchString(name) {
		return nil, "has a name with characters a windows_firewall_rule name can't take; it allows letters, digits, spaces and . _ ( ) -"
	}
	attrs := []attr{s("name", name)}
	if in.has("direction") {
		switch d := strings.ToLower(in.str("direction")); d {
		case "in":
		case "out":
			attrs = append(attrs, s("direction", "outbound"))
		default:
			return nil, fmt.Sprintf("has the direction %q", d)
		}
	}
	if in.has("action") {
		attrs = append(attrs, s("action", strings.ToLower(in.str("action"))))
	}
	if p := strings.ToLower(in.str("protocol")); p != "" && p != "any" {
		attrs = append(attrs, s("protocol", p))
	}
	if ports := in.list("localport"); len(ports) > 0 && !strings.EqualFold(ports[0], "any") {
		attrs = append(attrs, attr{key: "local_ports", val: strList(ports)})
	}
	if ips := in.list("remoteip"); len(ips) > 0 && !strings.EqualFold(ips[0], "any") {
		attrs = append(attrs, attr{key: "remote_addresses", val: strList(ips)})
	}
	if profiles := in.list("profiles"); len(profiles) > 0 && !strings.EqualFold(profiles[0], "any") {
		var lower []string
		for _, p := range profiles {
			lower = append(lower, strings.ToLower(p))
		}
		attrs = append(attrs, attr{key: "profiles", val: strList(lower)})
	}
	if in.has("enabled") {
		attrs = append(attrs, attr{key: "enabled", val: cty.BoolVal(in.bool("enabled", true))})
	}
	attrs = in.optional(attrs, "description", "description")
	return one("windows_firewall_rule", attrs, "Conn3x finds this rule by its ID, which is name; Ansible found it by its display name. If the rule Ansible made has another ID, delete it, or the two overlap.")
}

func strList(list []string) cty.Value {
	var v []cty.Value
	for _, s := range list {
		v = append(v, cty.StringVal(s))
	}
	return cty.ListVal(v)
}

func winPackageModule(in *input) ([]step, string) {
	code := strings.ToUpper(in.str("product_id"))
	if in.state("present", "present", "absent") == "absent" {
		if code == "" {
			return nil, "removes a package by its path; windows_package removes by product_code, so give it the MSI's ProductCode"
		}
		in.ignore("path", "arguments", "creates_path", "creates_service", "creates_version", "log_path")
		return one("windows_package", []attr{s("product_code", code), s("state", "absent")})
	}
	// Ansible's task has no checksum, and Conn3x installs only what it can check.
	return nil, "has no SHA-256 for the package; write a windows_package with product_code, source or url, and sha256"
}
