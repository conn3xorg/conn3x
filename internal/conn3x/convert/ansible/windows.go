// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
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

var (
	winTaskTriggers = map[string]string{"boot": "boot", "logon": "logon", "daily": "daily", "time": "once"}
	winTaskTime     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$`)
	winAbsolute     = regexp.MustCompile(`^[A-Za-z]:\\`)
)

// winSubMap reads one entry of a list of maps, refusing any key not in keys,
// so nothing a task sets is dropped without a person seeing it.
func (in *input) winSubMap(list string, n *yaml.Node, keys ...string) (map[string]string, string) {
	out := map[string]string{}
	for k, v := range mapping(n) {
		if !slices.Contains(keys, k) {
			return nil, fmt.Sprintf("sets %s in %s, which Conn3x has no setting for", k, list)
		}
		out[k] = in.render(list, scalar(v))
	}
	return out, ""
}

func winScheduledTaskModule(in *input) ([]step, string) {
	if in.state("present", "present", "absent") == "absent" {
		return nil, "removes a task; Conn3x deletes a windows_scheduled_task when its step goes, so there's nothing to convert this to yet"
	}
	actions := seq(in.args["actions"])
	in.used["actions"] = true
	if len(actions) != 1 {
		return nil, "has other than one action; windows_scheduled_task runs one program"
	}
	act, reason := in.winSubMap("actions", actions[0], "path", "arguments", "working_directory")
	if reason != "" {
		return nil, reason
	}
	if !winAbsolute.MatchString(act["path"]) {
		return nil, "runs a program without its full path; windows_scheduled_task needs one, such as C:\\Windows\\System32\\cmd.exe"
	}
	user := in.str("username")
	if user == "" {
		return nil, "doesn't name the user it runs as; windows_scheduled_task needs user"
	}
	switch lt := in.str("logon_type"); lt {
	case "", "service_account", "password", "s4u":
	default:
		return nil, fmt.Sprintf("has the logon_type %q, which windows_scheduled_task doesn't offer", lt)
	}
	attrs := []attr{s("name", in.str("name"))}
	attrs = in.optional(attrs, "path", "path")
	attrs = in.optional(attrs, "description", "description")
	attrs = append(attrs, s("execute", act["path"]))
	if v := act["arguments"]; v != "" {
		attrs = append(attrs, s("arguments", v))
	}
	if v := act["working_directory"]; v != "" {
		attrs = append(attrs, s("working_directory", v))
	}
	attrs = append(attrs, s("user", user))
	if rl := in.str("run_level"); rl != "" {
		attrs = append(attrs, s("run_level", rl))
	}
	if in.has("enabled") {
		attrs = append(attrs, attr{key: "enabled", val: cty.BoolVal(in.bool("enabled", true))})
	}
	var blocks []stepBlock
	in.used["triggers"] = true
	for _, n := range seq(in.args["triggers"]) {
		tr, reason := in.winSubMap("triggers", n, "type", "start_boundary", "days_interval")
		if reason != "" {
			return nil, reason
		}
		kind, ok := winTaskTriggers[tr["type"]]
		if !ok {
			return nil, fmt.Sprintf("has a %q trigger, which windows_scheduled_task doesn't offer", tr["type"])
		}
		b := []attr{s("type", kind)}
		if at := tr["start_boundary"]; at != "" && kind != "boot" && kind != "logon" {
			if !winTaskTime.MatchString(at) {
				return nil, "has a start_boundary that isn't a plain local time such as 2026-01-01T03:00:00"
			}
			b = append(b, s("at", at))
		}
		if d := tr["days_interval"]; d != "" {
			n, err := strconv.Atoi(d)
			if err != nil {
				return nil, "has a days_interval that isn't a number"
			}
			b = append(b, attr{key: "days_interval", val: cty.NumberIntVal(int64(n))})
		}
		blocks = append(blocks, stepBlock{name: "trigger", attrs: b})
	}
	var notes []string
	if in.has("password") {
		in.ignore("password", "update_password")
		notes = append(notes, "TODO(convert): Set password_wo from an ephemeral variable. The task's password isn't copied here.")
	}
	if windows.IsInterpreter(act["path"]) {
		attrs = append(attrs, attr{key: "allow_interpreter", val: cty.True})
		notes = append(notes, "TODO(convert): This task runs an interpreter. Conn3x checks paths it can see in arguments, not code inside them: make sure every script it runs is admin-only.")
	}
	return []step{{module: "windows_scheduled_task", attrs: attrs, blocks: blocks, notes: notes}}, ""
}

// winIISPoolAttributes are the app pool attributes windows_iis_app_pool sets,
// by their IIS names, which both Ansible collections use.
var winIISPoolAttributes = map[string]string{
	"managedRuntimeVersion": "managed_runtime_version", "managedPipelineMode": "pipeline_mode", "processModel.identityType": "identity",
}

// winIISState maps a pool or site state; restarted and absent have no step.
func (in *input) winIISState(def string) (string, string) {
	switch st := in.state(def, "present", "started", "stopped", "absent", "restarted"); st {
	case "absent":
		return "", "removes it; Conn3x deletes it when its step goes, so there's nothing to convert this to yet"
	case "restarted":
		return "", "restarts it on every run, which a step doesn't do"
	case "stopped":
		return "stopped", ""
	}
	return "", ""
}

// win_iis_webapppool, and microsoft.iis.web_app_pool, which replaces it.
func winIISAppPoolModule(in *input) ([]step, string) {
	state, reason := in.winIISState("present")
	if reason != "" {
		return nil, reason
	}
	attrs := []attr{s("name", in.str("name"))}
	if state != "" {
		attrs = append(attrs, s("state", state))
	}
	if n, ok := in.args["attributes"]; ok {
		in.used["attributes"] = true
		if n.Kind != yaml.MappingNode {
			return nil, "gives attributes as text; write them as a map"
		}
		m := mapping(n)
		for _, k := range sortedKeys(m) {
			to, ok := winIISPoolAttributes[k]
			if !ok {
				return nil, fmt.Sprintf("sets the attribute %s, which windows_iis_app_pool has no setting for", k)
			}
			v := in.render("attributes", scalar(m[k]))
			if to == "pipeline_mode" {
				v = strings.ToLower(v)
			}
			attrs = append(attrs, s(to, v))
		}
	}
	return one("windows_iis_app_pool", attrs)
}

// win_iis_website takes one binding as port, ip and hostname.
func winIISWebsiteModule(in *input) ([]step, string) {
	state, reason := in.winIISState("started")
	if reason != "" {
		return nil, reason
	}
	if !in.has("port") {
		return nil, "has no port; a windows_iis_site needs at least one binding"
	}
	port, err := strconv.Atoi(in.str("port"))
	if err != nil {
		return nil, "has a port that isn't a number"
	}
	b := []attr{{key: "port", val: cty.NumberIntVal(int64(port))}}
	if ip := in.str("ip"); ip != "" && ip != "*" {
		b = append(b, s("ip", ip))
	}
	b = in.optional(b, "host_header", "hostname")
	steps, reason := in.winIISSite(state, []stepBlock{{name: "binding", attrs: b}})
	if reason == "" {
		steps[0].notes = append(steps[0].notes, "TODO(convert): Ansible used port, ip and hostname only when it made the site. Here they're all of its bindings, so apply removes any other, such as one win_iis_webbinding added. Add a binding block for each one the site needs.")
	}
	return steps, reason
}

// microsoft.iis.website takes its bindings as bindings.set.
func winWebsiteModule(in *input) ([]step, string) {
	state, reason := in.winIISState("started")
	if reason != "" {
		return nil, reason
	}
	in.used["bindings"] = true
	m := mapping(in.args["bindings"])
	if len(m) != 1 || m["set"] == nil {
		return nil, "doesn't give its bindings as bindings.set; windows_iis_site needs the whole list"
	}
	var blocks []stepBlock
	for _, n := range seq(m["set"]) {
		bm, reason := in.winSubMap("bindings", n, "ip", "port", "hostname", "protocol")
		if reason != "" {
			return nil, reason
		}
		if p := bm["protocol"]; p != "" && p != "http" {
			return nil, "has an https binding; windows_iis_site supports http only for now"
		}
		port, err := strconv.Atoi(bm["port"])
		if err != nil {
			return nil, "has a binding without a numeric port"
		}
		b := []attr{{key: "port", val: cty.NumberIntVal(int64(port))}}
		if ip := bm["ip"]; ip != "" && ip != "*" {
			b = append(b, s("ip", ip))
		}
		if h := bm["hostname"]; h != "" {
			b = append(b, s("host_header", h))
		}
		blocks = append(blocks, stepBlock{name: "binding", attrs: b})
	}
	if len(blocks) == 0 {
		return nil, "has no bindings; a windows_iis_site needs at least one"
	}
	return in.winIISSite(state, blocks)
}

func (in *input) winIISSite(state string, blocks []stepBlock) ([]step, string) {
	if !in.has("physical_path") {
		return nil, "has no physical_path; windows_iis_site needs one"
	}
	attrs := []attr{s("name", in.str("name")), s("physical_path", in.str("physical_path"))}
	attrs = in.optional(attrs, "app_pool", "application_pool")
	if state != "" {
		attrs = append(attrs, s("state", state))
	}
	// Apply checks who can change the folder; a converted one usually fails that.
	note := "TODO(convert): Apply refuses a physical_path anyone but administrators can change, which a new folder with only inherited rules is, under C:\\inetpub or at the top of C:. Give its windows_directory acl blocks: SYSTEM and Administrators full, IIS_IUSRS and IUSR read."
	return []step{{module: "windows_iis_site", attrs: attrs, blocks: blocks, notes: []string{note}}}, ""
}

// winDomainModule converts microsoft.ad.domain and ansible.windows.win_domain,
// which both make a new forest.
func winDomainModule(in *input) ([]step, string) {
	if in.has("install_dns") && !in.bool("install_dns", true) {
		return nil, "makes a forest without DNS; windows_ad_forest always installs it"
	}
	for _, k := range []string{"domain_mode", "forest_mode", "create_dns_delegation", "dns_delegation_credential"} {
		if in.has(k) {
			return nil, "sets " + k + ", which windows_ad_forest doesn't offer yet; promote with Windows' defaults or by hand"
		}
	}
	attrs := []attr{s("domain_name", in.str("dns_domain_name"))}
	attrs = in.optional(attrs, "netbios_name", "domain_netbios_name")
	attrs = in.optional(attrs, "database_path", "database_path")
	attrs = in.optional(attrs, "log_path", "log_path")
	attrs = in.optional(attrs, "sysvol_path", "sysvol_path")
	// Never read, so a password can't end up in the output.
	in.ignore("safe_mode_password", "install_dns")
	forest := step{module: "windows_ad_forest", attrs: attrs, suffix: "forest",
		notes: []string{"TODO(convert): Set safe_mode_password_wo from an ephemeral variable. The task's password isn't copied here."}}
	return in.thenReboot(forest, true)
}

// winUpdateCategories are Windows Update's classifications by the names
// win_updates compares them with, lowercased; a windows_update category is
// the same name without its spaces.
var winUpdateCategories = []string{
	"applications", "connectors", "critical updates", "definition updates", "developer kits",
	"drivers", "feature packs", "guidance", "security updates", "service packs", "tools",
	"update rollups", "updates", "upgrades",
}

// winUpdateAliases are the run-together names win_updates.ps1 turns into
// Windows' own before it compares them.
var winUpdateAliases = map[string]string{
	"criticalupdates": "critical updates", "definitionupdates": "definition updates",
	"developerkits": "developer kits", "featurepacks": "feature packs",
	"securityupdates": "security updates", "servicepacks": "service packs",
	"updaterollups": "update rollups",
}

var winKB = regexp.MustCompile(`(?i)^KB[0-9]{6,8}$`)

// winUpdatesModule converts ansible.windows.win_updates. It installs one
// round of updates; with reboot, a windows_reboot step follows, but Ansible
// then searched and installed again until nothing was left, where Conn3x
// installs the rest at the next apply.
func winUpdatesModule(in *input) ([]step, string) {
	switch st := in.str("state"); st {
	case "", "installed":
	case "searched":
		in.ignore("category_names", "accept_list", "reject_list", "whitelist", "blacklist", "reboot", "reboot_timeout",
			"server_selection", "log_path", "skip_optional", "use_scheduled_task")
		return []step{{notes: []string{"win_updates with state searched only lists updates, so it changes nothing on hosts and is left out. A windows_update step's plan lists what's waiting in pending."}}}, ""
	case "downloaded":
		return nil, "only downloads updates, and windows_update installs them"
	default:
		return nil, fmt.Sprintf("state %q has no Conn3x equivalent here", st)
	}
	for _, c := range []struct{ key, why string }{
		{"log_path", "writes Windows Update's log to log_path, which windows_update doesn't"},
		{"maximum_retries_on_failed_updates", "retries updates that didn't take after a reboot, which windows_update doesn't"},
	} {
		if in.has(c.key) {
			return nil, c.why
		}
	}
	if sel := in.str("server_selection"); sel != "" && sel != "default" {
		return nil, fmt.Sprintf("has server_selection %s, and windows_update always uses the host's own update source", sel)
	}
	if in.bool("skip_optional", false) {
		return nil, "sets skip_optional, which windows_update has no setting for"
	}
	in.ignore("server_selection", "skip_optional", "use_scheduled_task")

	// Ansible's default is these three; windows_update's leaves out rollups.
	names := []string{"CriticalUpdates", "SecurityUpdates", "UpdateRollups"}
	if in.has("category_names") {
		names = in.list("category_names")
	}
	var cats []string
	seen := map[string]bool{}
	add := func(full string) {
		c := ""
		for _, w := range strings.Fields(full) {
			c += strings.ToUpper(w[:1]) + w[1:]
		}
		if !seen[c] {
			seen[c] = true
			cats = append(cats, c)
		}
	}
	for _, n := range names {
		if n == "*" {
			for _, full := range winUpdateCategories {
				add(full)
			}
			continue
		}
		full := strings.ToLower(n)
		if a, ok := winUpdateAliases[full]; ok {
			full = a
		}
		if !slices.Contains(winUpdateCategories, full) {
			return nil, fmt.Sprintf("names the category %q, which windows_update has no category for; win_updates also matches products, such as Windows Server 2019, and those have no equivalent", n)
		}
		add(full)
	}
	vals := make([]cty.Value, len(cats))
	for i, c := range cats {
		vals[i] = cty.StringVal(c)
	}
	attrs := []attr{{key: "categories", val: cty.ListVal(vals)}}

	for _, l := range []struct {
		to   string
		from []string
	}{
		{"accept_list", []string{"accept_list", "whitelist"}},
		{"reject_list", []string{"reject_list", "blacklist"}},
	} {
		if in.has(l.from[0]) && in.has(l.from[1]) {
			return nil, fmt.Sprintf("sets both %s and its old name %s, and Ansible uses only one of them", l.from[0], l.from[1])
		}
		for _, from := range l.from {
			if !in.has(from) {
				continue
			}
			var kbs []cty.Value
			for _, e := range in.list(from) {
				if !winKB.MatchString(e) {
					return nil, fmt.Sprintf("has %q in %s; win_updates takes titles and patterns there too, and windows_update only KB numbers", e, from)
				}
				kbs = append(kbs, cty.StringVal(strings.ToUpper(e)))
			}
			if len(kbs) > 0 {
				attrs = append(attrs, attr{key: l.to, val: cty.ListVal(kbs)})
			}
		}
	}

	update := step{module: "windows_update", attrs: attrs, suffix: "updates"}
	if !in.bool("reboot", false) {
		in.ignore("reboot_timeout")
		return []step{update}, ""
	}
	update.notes = []string{"Ansible installed, rebooted and searched again until nothing was left. This installs one round each apply: what the reboot unlocks shows in pending at the next plan, and the next apply installs it."}
	steps, why := in.thenReboot(update, false)
	if why != "" {
		return nil, why
	}
	// win_updates waits 1200 seconds for the host by default, and
	// windows_reboot 10 minutes, so the default is written out too.
	if !in.has("reboot_timeout") {
		steps[1].attrs = append(steps[1].attrs, s("timeout", "1200s"))
	}
	return steps, ""
}

// thenReboot follows a step that leaves a reboot pending with the reboot,
// when the task asked Ansible to reboot, since Conn3x modules never do. With
// adws, it then waits for AD, because sshd answers before AD does.
func (in *input) thenReboot(first step, adws bool) ([]step, string) {
	if !in.bool("reboot", false) {
		in.ignore("reboot_timeout")
		return []step{first}, ""
	}
	reboot := []attr{{key: "only_if_pending", val: cty.True}}
	if in.has("reboot_timeout") {
		secs, err := strconv.Atoi(in.str("reboot_timeout"))
		if err != nil || secs <= 0 {
			return nil, "has a reboot_timeout that isn't a positive number of seconds"
		}
		reboot = append(reboot, s("timeout", fmt.Sprintf("%ds", secs)))
	}
	steps := []step{first, {module: "windows_reboot", suffix: "reboot", attrs: reboot}}
	if adws {
		steps = append(steps, step{module: "windows_wait_for", suffix: "adws", attrs: []attr{{key: "port", val: cty.NumberIntVal(9389)}}})
	}
	return steps, ""
}

// winMembershipModule converts microsoft.ad.membership and
// ansible.windows.win_domain_membership, which join a domain or leave one.
func winMembershipModule(in *input) ([]step, string) {
	if st := in.str("state"); st != "domain" {
		return nil, fmt.Sprintf("has state %q; windows_domain_membership only joins a domain, and Conn3x never takes a host out of one", st)
	}
	for _, c := range []struct{ key, why string }{
		{"offline_join_blob", "joins offline with a blob, which windows_domain_membership doesn't do; join with an account instead"},
		{"hostname", "renames the host as it joins, which Conn3x doesn't do on Windows yet"},
		{"domain_server", "names the domain controller to join through, which windows_domain_membership doesn't offer yet"},
	} {
		if in.has(c.key) {
			return nil, c.why
		}
	}
	if !in.has("domain_admin_user") {
		return nil, "has no domain_admin_user; windows_domain_membership joins with an account named in username"
	}
	attrs := []attr{s("domain", in.str("dns_domain_name")), s("username", in.str("domain_admin_user"))}
	attrs = in.optional(attrs, "ou", "domain_ou_path")
	// Never read, so a password can't end up in the output.
	in.ignore("domain_admin_password", "workgroup_name")
	join := step{module: "windows_domain_membership", attrs: attrs, suffix: "join",
		notes: []string{"TODO(convert): Set password_wo from an ephemeral variable. The task's password isn't copied here."}}
	return in.thenReboot(join, false)
}

// winDCModule converts microsoft.ad.domain_controller and
// ansible.windows.win_domain_controller, which promote another domain
// controller or demote one.
func winDCModule(in *input) ([]step, string) {
	if st := in.str("state"); st != "domain_controller" {
		return nil, fmt.Sprintf("has state %q; windows_ad_domain_controller only promotes, and Conn3x never demotes a domain controller", st)
	}
	if in.has("install_dns") && !in.bool("install_dns", true) {
		return nil, "promotes without DNS; windows_ad_domain_controller always installs it"
	}
	if in.bool("read_only", false) {
		return nil, "makes a read-only domain controller, which windows_ad_domain_controller doesn't offer yet"
	}
	for _, k := range []string{"site_name", "install_media_path", "replication_source_dc"} {
		if in.has(k) {
			return nil, "sets " + k + ", which windows_ad_domain_controller doesn't offer yet; promote with Windows' defaults or by hand"
		}
	}
	if !in.has("domain_admin_user") {
		return nil, "has no domain_admin_user; windows_ad_domain_controller promotes with an account named in username"
	}
	attrs := []attr{s("domain_name", in.str("dns_domain_name")), s("username", in.str("domain_admin_user"))}
	attrs = in.optional(attrs, "database_path", "database_path")
	attrs = in.optional(attrs, "log_path", "domain_log_path")
	attrs = in.optional(attrs, "sysvol_path", "sysvol_path")
	// Never read, so a password can't end up in the output.
	in.ignore("domain_admin_password", "safe_mode_password", "local_admin_password", "install_dns", "read_only")
	dc := step{module: "windows_ad_domain_controller", attrs: attrs, suffix: "dc",
		notes: []string{"TODO(convert): Set password_wo and safe_mode_password_wo from ephemeral variables. The task's passwords aren't copied here."}}
	return in.thenReboot(dc, true)
}

// winChildDomainModule converts microsoft.ad.domain_child, which makes a
// child domain under one in the forest, or a new tree in it.
func winChildDomainModule(in *input) ([]step, string) {
	if t := in.str("domain_type"); t != "" && t != "child" {
		return nil, fmt.Sprintf("has domain_type %q; windows_ad_domain only makes a child of an existing domain, not a new tree", t)
	}
	if in.has("install_dns") && !in.bool("install_dns", true) {
		return nil, "makes the domain without DNS; windows_ad_domain always installs it"
	}
	for _, k := range []string{"domain_mode", "create_dns_delegation", "site_name", "replication_source_dc", "parent_domain_name"} {
		if in.has(k) {
			return nil, "sets " + k + ", which windows_ad_domain doesn't offer yet; make the domain with Windows' defaults or by hand"
		}
	}
	if !in.has("domain_admin_user") {
		return nil, "has no domain_admin_user; windows_ad_domain makes the domain with an account named in username"
	}
	user := in.str("domain_admin_user")
	if !dnsQualified(user) {
		return nil, fmt.Sprintf("names the account as %q; windows_ad_domain needs it with its domain's DNS name, such as admin@lab.example.com or lab.example.com\\admin", user)
	}
	attrs := []attr{s("domain_name", in.str("dns_domain_name")), s("username", user)}
	attrs = in.optional(attrs, "database_path", "database_path")
	attrs = in.optional(attrs, "log_path", "log_path")
	attrs = in.optional(attrs, "sysvol_path", "sysvol_path")
	// Never read, so a password can't end up in the output.
	in.ignore("domain_admin_password", "safe_mode_password", "install_dns", "domain_type")
	child := step{module: "windows_ad_domain", attrs: attrs, suffix: "domain",
		notes: []string{"TODO(convert): Set password_wo and safe_mode_password_wo from ephemeral variables. The task's passwords aren't copied here."}}
	return in.thenReboot(child, true)
}

// dnsQualified reports whether an account is named by its domain's DNS name,
// as admin@lab.example.com or lab.example.com\admin, not LAB\admin.
func dnsQualified(user string) bool {
	if name, domain, ok := strings.Cut(user, "@"); ok {
		return name != "" && strings.Contains(domain, ".")
	}
	domain, name, ok := strings.Cut(user, `\`)
	return ok && name != "" && strings.Contains(domain, ".")
}

func winDNSClientModule(in *input) ([]step, string) {
	adapters := in.list("adapter_names")
	if len(adapters) != 1 || strings.ContainsAny(adapters[0], "*?[]`") {
		return nil, "names several adapters, all of them, or one with wildcard characters; give each a windows_dns_client step with its exact name, or leave interface unset for the one with the default route"
	}
	servers := in.list("dns_servers")
	if len(servers) == 0 {
		servers = in.list("ipv4_addresses")
	}
	if len(servers) == 0 {
		return nil, "resets DNS to DHCP, which windows_dns_client doesn't do"
	}
	vals := make([]cty.Value, len(servers))
	for i, v := range servers {
		vals[i] = cty.StringVal(v)
	}
	return one("windows_dns_client", []attr{s("interface", adapters[0]), {key: "servers", val: cty.ListVal(vals)}})
}

// adCommon refuses what the microsoft.ad modules and their community.windows
// forerunners share and Conn3x doesn't do: removal by state, and reaching
// another server or using other credentials. Conn3x runs these on a domain
// controller as its login. A sam_account_name other than name goes to a
// person too, as Conn3x uses one name for both.
func (in *input) adCommon(what string) string {
	if in.state("present", "present", "absent") == "absent" {
		return fmt.Sprintf("removes a %s; Conn3x deletes one with on_remove = \"delete\" when its step goes, so there's nothing to convert this to yet", what)
	}
	for _, k := range []string{"domain_server", "domain_username", "domain_password", "domain_credentials"} {
		if in.has(k) {
			return "sets " + k + "; Conn3x runs AD steps on a domain controller as its own login, so run the step there"
		}
	}
	if in.has("identity") {
		return "finds the object by identity, to rename or move it; Conn3x finds it by name"
	}
	if in.has("sam_account_name") && !strings.EqualFold(in.str("sam_account_name"), in.str("name")) {
		return "gives a sam_account_name other than its name; Conn3x uses one name for both"
	}
	return ""
}

// adPath adds path, unless it's the module's way of saying the default.
func (in *input) adPath(attrs []attr, from ...string) []attr {
	for _, f := range from {
		if in.has(f) {
			if p := in.str(f); p != "microsoft.ad.default_path" {
				return append(attrs, s("path", p))
			}
		}
	}
	return attrs
}

func (in *input) adBool(attrs []attr, to, from string) []attr {
	if in.has(from) {
		return append(attrs, attr{key: to, val: cty.BoolVal(in.bool(from, false))})
	}
	return attrs
}

// winADOUModule converts microsoft.ad.ou.
func winADOUModule(in *input) ([]step, string) {
	if why := in.adCommon("OU"); why != "" {
		return nil, why
	}
	attrs := in.adPath([]attr{s("name", in.str("name"))}, "path")
	attrs = in.optional(attrs, "description", "description")
	attrs = in.adBool(attrs, "protected", "protect_from_deletion")
	return one("windows_ad_ou", attrs)
}

// adMember is a member windows_ad_group can take: a sAMAccountName, not a DN,
// a UPN, DOMAIN\name, a SID or a GUID.
var adMember = regexp.MustCompile(`^[^"/\\\[\]:;|=,+*?<>@{}]{1,256}$`)

// winADGroupModule converts microsoft.ad.group and community.windows'
// win_domain_group.
func winADGroupModule(in *input) ([]step, string) {
	if why := in.adCommon("group"); why != "" {
		return nil, why
	}
	attrs := in.adPath([]attr{s("name", in.str("name"))}, "path", "organizational_unit", "ou")
	if in.has("scope") {
		attrs = append(attrs, s("scope", strings.ToLower(in.str("scope"))))
	}
	if in.has("category") {
		attrs = append(attrs, s("category", strings.ToLower(in.str("category"))))
	}
	attrs = in.optional(attrs, "description", "description")
	n, ok := in.args["members"]
	if !ok {
		return one("windows_ad_group", attrs)
	}
	in.used["members"] = true
	m := mapping(n)
	if n.Kind != yaml.MappingNode {
		return nil, "gives members that aren't add, set or remove lists"
	}
	if _, ok := m["remove"]; ok {
		return nil, "takes members out by name; windows_ad_group adds them, or keeps the complete list with authoritative = true"
	}
	if a := scalar(m["lookup_failure_action"]); a != "" && a != "fail" {
		return nil, "sets lookup_failure_action " + a + "; windows_ad_group fails on a member that doesn't exist"
	}
	list, auth := m["add"], false
	if set, ok := m["set"]; ok {
		if list != nil {
			return nil, "both adds and sets members; pick one"
		}
		list, auth = set, true
	}
	for k := range m {
		if k != "add" && k != "set" && k != "lookup_failure_action" {
			return nil, "sets " + k + " in members, which windows_ad_group has no setting for"
		}
	}
	vals := []cty.Value{}
	for _, e := range seq(list) {
		v := in.render("members", scalar(e))
		if e.Kind != yaml.ScalarNode || !adMember.MatchString(v) {
			return nil, "names a member by something other than its sAMAccountName, such as a DN, DOMAIN\\name, a UPN or a SID; windows_ad_group takes names such as alice or web1$"
		}
		vals = append(vals, cty.StringVal(v))
	}
	if len(vals) == 0 && !auth {
		return one("windows_ad_group", attrs)
	}
	if len(vals) == 0 {
		attrs = append(attrs, attr{key: "members", val: cty.ListValEmpty(cty.String)})
	} else {
		attrs = append(attrs, attr{key: "members", val: cty.ListVal(vals)})
	}
	if auth {
		attrs = append(attrs, attr{key: "authoritative", val: cty.True})
	}
	return one("windows_ad_group", attrs)
}

// winADUserModule converts microsoft.ad.user and community.windows'
// win_domain_user.
func winADUserModule(in *input) ([]step, string) {
	if in.str("state") == "query" {
		return nil, "only queries a user, which a step doesn't do"
	}
	if why := in.adCommon("user"); why != "" {
		return nil, why
	}
	if in.has("groups") {
		return nil, "sets groups; give each group a windows_ad_group step with this user in its members"
	}
	attrs := in.adPath([]attr{s("name", in.str("name"))}, "path")
	attrs = in.optional(attrs, "upn", "upn")
	attrs = in.optional(attrs, "given_name", "firstname")
	attrs = in.optional(attrs, "surname", "surname", "lastname")
	attrs = in.optional(attrs, "display_name", "display_name")
	attrs = in.optional(attrs, "description", "description")
	attrs = in.adBool(attrs, "enabled", "enabled")
	attrs = in.adBool(attrs, "password_never_expires", "password_never_expires")
	// Never read, so a password can't end up in the output. Conn3x sets one
	// when the user is made and when it changes, whatever update_password says.
	in.ignore("update_password")
	var notes []string
	if in.has("password") {
		in.ignore("password")
		notes = append(notes, "TODO(convert): Set password_wo from an ephemeral variable. The task's password isn't copied here.")
	}
	return one("windows_ad_user", attrs, notes...)
}
