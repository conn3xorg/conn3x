// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"

	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
	"github.com/opentofu/opentofu/internal/conn3x/modules/repo"
	"github.com/opentofu/opentofu/internal/conn3x/modules/system"
)

const (
	hclsyntaxComment = hclsyntax.TokenComment
	hclsyntaxIdent   = hclsyntax.TokenIdent
)

// step is one Conn3x step a task becomes.
type step struct {
	module string
	attrs  []attr
	notes  []string
	suffix string // tells apart several steps from one task
}

type attr struct {
	key string
	val cty.Value
	raw string // an expression, when set
}

// input reads a task's arguments, remembering which it used so that any it
// didn't stop the conversion.
type input struct {
	args     map[string]*yaml.Node
	vars     map[string]string
	dir      string
	used     map[string]bool
	problem  string
	loop     bool // the task loops, so {{ item }} means the current item
	itemUsed bool
}

func (in *input) has(key string) bool { _, ok := in.args[key]; return ok }

// str returns an argument, with simple {{ var }} references to play vars
// filled in. Anything else in braces is a problem for a person.
func (in *input) str(keys ...string) string {
	for _, k := range keys {
		n, ok := in.args[k]
		if !ok {
			continue
		}
		in.used[k] = true
		if n.Kind != yaml.ScalarNode {
			in.fail(k + " is not a single value")
			return ""
		}
		return in.render(k, n.Value)
	}
	return ""
}

func (in *input) list(key string) []string {
	n, ok := in.args[key]
	if !ok {
		return nil
	}
	in.used[key] = true
	var out []string
	if n.Kind == yaml.ScalarNode {
		for _, s := range strings.Split(n.Value, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, in.render(key, s))
			}
		}
		return out
	}
	for _, e := range seq(n) {
		out = append(out, in.render(key, scalar(e)))
	}
	return out
}

func (in *input) bool(key string, def bool) bool {
	if !in.has(key) {
		return def
	}
	return truthy(in.str(key))
}

// ignore marks arguments that change nothing Conn3x would do differently.
func (in *input) ignore(keys ...string) {
	for _, k := range keys {
		in.used[k] = true
	}
}

func (in *input) fail(reason string) {
	if in.problem == "" {
		in.problem = reason
	}
}

func (in *input) unused() []string {
	var out []string
	for k := range in.args {
		if !in.used[k] && k != "_raw" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

var jinja = regexp.MustCompile(`\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)

func (in *input) render(key, s string) string {
	out := jinja.ReplaceAllStringFunc(s, func(m string) string {
		name := jinja.FindStringSubmatch(m)[1]
		if name == "item" && in.loop {
			in.itemUsed = true
			return itemMark
		}
		if v, ok := in.vars[name]; ok {
			return v
		}
		in.fail(fmt.Sprintf("%s refers to %q, which isn't a play variable the converter can fill in", key, name))
		return m
	})
	if strings.Contains(out, "{{") || strings.Contains(out, "{%") {
		in.fail(key + " uses a Jinja expression the converter can't translate")
	}
	return out
}

// mode turns an Ansible mode into four octal digits. An unquoted 644 is
// read the way it was obviously meant.
func (in *input) mode(key string) (attr, bool) {
	m := in.str(key)
	if m == "" {
		return attr{}, false
	}
	m = strings.TrimPrefix(m, "0o")
	switch {
	case regexp.MustCompile(`^[0-7]{3}$`).MatchString(m):
		m = "0" + m
	case regexp.MustCompile(`^[0-7]{4}$`).MatchString(m):
	default:
		in.fail(fmt.Sprintf("mode %q is not an octal mode", m))
		return attr{}, false
	}
	return attr{key: "mode", val: cty.StringVal(m)}, true
}

func s(key, v string) attr { return attr{key: key, val: cty.StringVal(v)} }

// optional adds an attribute when the argument is set.
func (in *input) optional(attrs []attr, to string, from ...string) []attr {
	for _, f := range from {
		if in.has(f) {
			return append(attrs, s(to, in.str(f)))
		}
	}
	return attrs
}

func (in *input) owners(attrs []attr) []attr {
	attrs = in.optional(attrs, "owner", "owner")
	return in.optional(attrs, "group", "group")
}

// state checks the state argument is one of allowed, defaulting to def.
func (in *input) state(def string, allowed ...string) string {
	st := def
	if in.has("state") {
		st = in.str("state")
	}
	for _, a := range allowed {
		if st == a {
			return st
		}
	}
	in.fail(fmt.Sprintf("state %q has no Conn3x equivalent here", st))
	return st
}

// local finds a file the playbook refers to, the way Ansible looks for it.
func (in *input) local(sub, name string) string {
	for _, p := range []string{filepath.Join(sub, name), name} {
		if _, err := os.Stat(filepath.Join(in.dir, p)); err == nil {
			return filepath.ToSlash(p)
		}
	}
	in.fail(fmt.Sprintf("%s was not found beside the playbook or in %s/", name, sub))
	return ""
}

func one(module string, attrs []attr, notes ...string) ([]step, string) {
	return []step{{module: module, attrs: attrs, notes: notes}}, ""
}

// modules maps Ansible module names to their translations.
var modules = map[string]func(*input) ([]step, string){
	"copy":            copyModule,
	"file":            fileModule,
	"lineinfile":      lineModule,
	"blockinfile":     blockModule,
	"template":        templateModule,
	"package":         packageModule,
	"dnf":             packageModule,
	"yum":             packageModule,
	"apt":             packageModule,
	"service":         serviceModule,
	"systemd":         serviceModule,
	"systemd_service": serviceModule,
	"user":            userModule,
	"group":           groupModule,
	"authorized_key":  authorizedKeyModule,
	"cron":            cronModule,
	"sysctl":          sysctlModule,
	"hostname":        nameOnly("hostname"),
	"timezone":        nameOnly("timezone"),
	"firewalld":       firewalldModule,
	"ufw":             ufwModule,
	"seboolean":       sebooleanModule,
	"sefcontext":      sefcontextModule,
	"get_url":         getURLModule,
	"unarchive":       unarchiveModule,
	"git":             gitModule,
	"mount":           mountModule,
	"command":         commandModule,
	"shell":           commandModule,
	"reboot":          rebootModule,
	"wait_for":        waitForModule,
	"apt_repository":  aptRepositoryModule,
	"yum_repository":  yumRepositoryModule,
	"locale_gen":      localeGenModule,
}

func copyModule(in *input) ([]step, string) {
	attrs := []attr{s("path", in.str("dest"))}
	switch {
	case in.has("content"):
		attrs = append(attrs, s("content", in.str("content")))
	case in.has("src"):
		if p := in.local("files", in.str("src")); p != "" {
			attrs = append(attrs, attr{key: "content", raw: fmt.Sprintf(`file("${path.module}/%s")`, p)})
		}
		if in.has("remote_src") && in.bool("remote_src", false) {
			return nil, "copies a file already on the host (remote_src), which the converter can't translate yet"
		}
	default:
		return nil, "has neither content nor src"
	}
	if m, ok := in.mode("mode"); ok {
		attrs = append(attrs, m)
	}
	if !in.bool("force", true) {
		return nil, "sets force: no, so Ansible writes the file only when it's missing; Conn3x would replace it on every apply"
	}
	in.ignore("backup")
	return one("file", in.owners(attrs))
}

func fileModule(in *input) ([]step, string) {
	path := in.str("path", "dest", "name")
	switch in.state("file", "directory", "link", "file", "absent", "touch") {
	case "directory":
		attrs := []attr{s("path", path)}
		if m, ok := in.mode("mode"); ok {
			attrs = append(attrs, m)
		}
		if in.bool("recurse", false) {
			return nil, "sets recurse, which the converter can't translate yet"
		}
		in.ignore("recurse")
		return one("directory", in.owners(attrs))
	case "link":
		if in.has("owner") || in.has("group") || in.has("mode") {
			return nil, "sets owner, group or mode on a link, which a Conn3x link step doesn't manage"
		}
		return one("link", []attr{s("path", path), s("target", in.str("src"))})
	}
	return nil, "changes an existing file's attributes or removes it, which the converter can't translate yet"
}

func editTarget(in *input) []attr {
	attrs := []attr{s("path", in.str("path", "dest", "name"))}
	attrs = in.optional(attrs, "insert_after", "insertafter")
	attrs = in.optional(attrs, "insert_before", "insertbefore")
	if in.has("create") {
		attrs = append(attrs, attr{key: "create", val: cty.BoolVal(in.bool("create", false))})
	}
	if st := in.state("present", "present", "absent"); st != "present" {
		attrs = append(attrs, s("state", st))
	}
	return attrs
}

func lineModule(in *input) ([]step, string) {
	attrs := editTarget(in)
	attrs = in.optional(attrs, "line", "line")
	attrs = in.optional(attrs, "regexp", "regexp", "regex")
	if in.bool("backrefs", false) {
		return nil, "uses backrefs, which the converter can't translate yet"
	}
	in.ignore("backrefs", "backup")
	return one("line", attrs)
}

func blockModule(in *input) ([]step, string) {
	attrs := editTarget(in)
	attrs = append(attrs, s("content", in.str("block", "content")))
	marker := "# {mark} ANSIBLE MANAGED BLOCK"
	if in.has("marker") {
		marker = in.str("marker")
	}
	attrs = append(attrs, s("marker", marker))
	if in.has("marker_begin") || in.has("marker_end") {
		return nil, "sets marker_begin or marker_end, which the converter can't translate yet"
	}
	in.ignore("backup")
	return one("block", attrs, "Keeps Ansible's marker, so the block it already wrote is the one Conn3x manages.")
}

func templateModule(in *input) ([]step, string) {
	in.ignore("src", "dest", "mode", "owner", "group")
	return nil, "renders a Jinja template; rewrite it in templatefile syntax (${var}, %{ if }) and use a template step"
}

func packageModule(in *input) ([]step, string) {
	names := in.list("name")
	if len(names) == 0 {
		names = in.list("pkg")
	}
	st := in.state("present", "present", "installed", "latest", "absent", "removed")
	if alias, ok := map[string]string{"installed": "present", "removed": "absent"}[st]; ok {
		st = alias
	}
	var notes []string
	if in.has("update_cache") {
		in.ignore("update_cache", "cache_valid_time")
		notes = append(notes, "update_cache dropped: Conn3x refreshes the package lists when a package isn't found.")
	}
	var steps []step
	for _, n := range names {
		attrs := []attr{s("name", n)}
		if st != "present" {
			attrs = append(attrs, s("state", st))
		}
		steps = append(steps, step{module: "package", attrs: attrs, notes: notes, suffix: n})
		notes = nil
	}
	if len(steps) == 0 {
		return nil, "names no package"
	}
	return steps, ""
}

func serviceModule(in *input) ([]step, string) {
	attrs := []attr{s("name", in.str("name"))}
	if in.has("state") {
		st := in.state("", "started", "stopped")
		attrs = append(attrs, s("state", st))
	}
	if in.has("enabled") {
		attrs = append(attrs, attr{key: "enabled", val: cty.BoolVal(in.bool("enabled", false))})
	}
	var notes []string
	if in.has("daemon_reload") {
		in.ignore("daemon_reload")
		notes = append(notes, "daemon_reload dropped: Conn3x reloads systemd when a unit file changed.")
	}
	return one("service", attrs, notes...)
}

func userModule(in *input) ([]step, string) {
	in.state("present", "present")
	attrs := []attr{s("name", in.str("name"))}
	if in.has("uid") {
		attrs = append(attrs, attr{key: "uid", raw: in.str("uid")})
	}
	attrs = in.optional(attrs, "group", "group")
	if in.has("groups") {
		if in.bool("append", false) {
			return nil, "appends to the user's groups; Conn3x sets the full list"
		}
		in.ignore("append")
		var vals []cty.Value
		for _, g := range in.list("groups") {
			vals = append(vals, cty.StringVal(g))
		}
		if len(vals) > 0 {
			attrs = append(attrs, attr{key: "groups", val: cty.ListVal(vals)})
		}
	}
	attrs = in.optional(attrs, "home", "home")
	attrs = in.optional(attrs, "shell", "shell")
	if in.has("system") {
		attrs = append(attrs, attr{key: "system", val: cty.BoolVal(in.bool("system", false))})
	}
	if !in.bool("create_home", true) {
		return nil, "sets create_home: no; Conn3x always creates the home directory"
	}
	return one("user", attrs)
}

func groupModule(in *input) ([]step, string) {
	in.state("present", "present")
	attrs := []attr{s("name", in.str("name"))}
	if in.has("gid") {
		attrs = append(attrs, attr{key: "gid", raw: in.str("gid")})
	}
	if in.has("system") {
		attrs = append(attrs, attr{key: "system", val: cty.BoolVal(in.bool("system", false))})
	}
	return one("group", attrs)
}

func authorizedKeyModule(in *input) ([]step, string) {
	in.state("present", "present")
	return one("authorized_key", []attr{s("user", in.str("user")), s("key", in.str("key"))})
}

var cronName = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

func cronModule(in *input) ([]step, string) {
	in.state("present", "present")
	if in.has("cron_file") {
		return nil, "writes to a named cron_file, which the converter can't translate yet"
	}
	schedule := ""
	if in.has("special_time") {
		schedule = "@" + in.str("special_time")
	} else {
		var fields []string
		for _, k := range []string{"minute", "hour", "day", "month", "weekday"} {
			v := "*"
			if in.has(k) {
				v = in.str(k)
			}
			fields = append(fields, v)
		}
		schedule = strings.Join(fields, " ")
	}
	name := strings.Trim(cronName.ReplaceAllString(in.str("name"), "-"), "-")
	attrs := []attr{s("name", name), s("schedule", schedule), s("command", in.str("job"))}
	attrs = in.optional(attrs, "user", "user")
	return one("cron", attrs, "Conn3x keeps the job in /etc/cron.d rather than the user's crontab.",
		fmt.Sprintf("TODO(convert): Delete the \"#Ansible: %s\" job Ansible left in the user's crontab, or it runs twice.", in.str("name")))
}

func sysctlModule(in *input) ([]step, string) {
	in.state("present", "present")
	if in.has("sysctl_file") {
		return nil, "writes to a named sysctl_file, which the converter can't translate yet"
	}
	in.ignore("reload", "sysctl_set")
	return one("sysctl", []attr{s("name", in.str("name")), s("value", in.str("value"))})
}

func nameOnly(module string) func(*input) ([]step, string) {
	return func(in *input) ([]step, string) {
		in.ignore("use")
		return one(module, []attr{s("name", in.str("name"))})
	}
}

func firewalldModule(in *input) ([]step, string) {
	in.state("enabled", "enabled")
	if !in.bool("permanent", false) || !in.bool("immediate", false) {
		return nil, "doesn't set both permanent and immediate; Conn3x always changes both"
	}
	attrs := in.optional(nil, "zone", "zone")
	attrs = in.optional(attrs, "service", "service")
	attrs = in.optional(attrs, "port", "port")
	return one("firewalld", attrs)
}

func ufwModule(in *input) ([]step, string) {
	if !in.has("rule") {
		return nil, "changes ufw itself rather than adding a rule; use a guarded command step"
	}
	port := in.str("port", "to_port")
	if in.has("proto") {
		if p := in.str("proto"); p != "any" {
			port += "/" + p
		}
	}
	attrs := []attr{s("action", in.str("rule")), s("port", port)}
	attrs = in.optional(attrs, "from", "from_ip", "from", "src")
	return one("ufw", attrs)
}

func sebooleanModule(in *input) ([]step, string) {
	if !in.bool("persistent", false) {
		return nil, "sets the boolean until reboot only; Conn3x always makes it persistent"
	}
	return one("selinux_boolean", []attr{s("name", in.str("name")), {key: "value", val: cty.BoolVal(in.bool("state", false))}})
}

func sefcontextModule(in *input) ([]step, string) {
	in.state("present", "present")
	in.ignore("reload")
	return one("selinux_fcontext", []attr{s("target", in.str("target")), s("setype", in.str("setype"))})
}

func getURLModule(in *input) ([]step, string) {
	sum := in.str("checksum")
	if !strings.HasPrefix(sum, "sha256:") {
		return nil, "has no sha256 checksum; Conn3x downloads only what it can verify"
	}
	attrs := []attr{s("url", in.str("url")), s("dest", in.str("dest")), s("sha256", strings.TrimPrefix(sum, "sha256:"))}
	if m, ok := in.mode("mode"); ok {
		attrs = append(attrs, m)
	}
	return one("download", in.owners(attrs))
}

func unarchiveModule(in *input) ([]step, string) {
	if !in.bool("remote_src", false) {
		return nil, "unpacks a file from the controller; download it first, then use an archive step"
	}
	if !in.has("creates") {
		return nil, "has no creates guard; Conn3x needs one to know when the archive is unpacked"
	}
	return one("archive", []attr{s("src", in.str("src")), s("dest", in.str("dest")), s("creates", in.str("creates"))})
}

func gitModule(in *input) ([]step, string) {
	attrs := []attr{s("repo", in.str("repo")), s("dest", in.str("dest"))}
	attrs = in.optional(attrs, "ref", "version")
	return one("git", attrs)
}

func mountModule(in *input) ([]step, string) {
	in.state("mounted", "mounted")
	attrs := []attr{s("path", in.str("path", "name")), s("src", in.str("src")), s("fstype", in.str("fstype"))}
	attrs = in.optional(attrs, "opts", "opts")
	in.ignore("dump", "passno")
	return one("mount", attrs)
}

func commandModule(in *input) ([]step, string) {
	cmd := in.str("cmd")
	if n, ok := in.args["_raw"]; ok {
		for _, f := range strings.Fields(n.Value) {
			if k, _, ok := strings.Cut(f, "="); ok && inlineArgs[k] {
				return nil, "sets " + k + " inside the command line; move it under args so the converter can read it"
			}
		}
		cmd = in.render("command", n.Value)
	}
	if cmd == "" {
		return nil, "has no command"
	}
	if in.has("chdir") {
		cmd = "cd " + shellQuote(in.str("chdir")) + " && " + cmd
	}
	attrs := []attr{s("command", cmd)}
	attrs = in.optional(attrs, "creates", "creates")
	attrs = in.optional(attrs, "removes", "removes")
	for _, k := range []string{"creates", "removes"} {
		if strings.ContainsAny(in.str(k), "*?[") {
			return nil, k + " is a glob pattern; Conn3x tests the path as written"
		}
	}
	in.ignore("executable")
	if !in.has("creates") && !in.has("removes") {
		return nil, "runs on every play; give it a creates, removes or unless guard, or triggers, so Conn3x knows when it's done"
	}
	return one("command", attrs)
}

func rebootModule(in *input) ([]step, string) {
	in.ignore("reboot_timeout", "msg")
	return nil, "reboots on every play; a Conn3x reboot step reboots once, and again when its triggers change, so add triggers"
}

func waitForModule(in *input) ([]step, string) {
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
	in.ignore("delay")
	return one("wait_for", attrs)
}

// aptLine is a one-line apt source: deb, optional [options], URL, suite and
// any components. Anything else, such as deb-src or a ppa: name, doesn't match.
var aptLine = regexp.MustCompile(`^deb(?:\s+\[([^\]]*)\])?\s+(\S+)\s+(\S+)((?:\s+\S+)*)$`)

var keyFileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+-]*$`)

// repoKey finds the armored key a playbook names by URL or host path. Conn3x
// needs the key itself, and the converter doesn't download anything, so it has
// to be beside the playbook under the same file name.
func (in *input) repoKey(from string) (key, file, reason string) {
	u, err := url.Parse(from)
	if err != nil {
		return "", "", fmt.Sprintf("names the signing key %q, which the converter can't read as a path or URL", from)
	}
	base := path.Base(u.Path)
	if !keyFileName.MatchString(base) {
		return "", "", fmt.Sprintf("names the signing key %q, which has no usable file name", from)
	}
	file = in.local("files", base)
	if file == "" {
		return "", "", fmt.Sprintf("needs the signing key itself, which Conn3x stores on the host; save %s as files/%s beside the playbook and convert again", from, base)
	}
	data, err := os.ReadFile(filepath.Join(in.dir, file))
	if err != nil {
		return "", "", fmt.Sprintf("can't read the signing key %s: %v", file, err)
	}
	return string(data), file, ""
}

func stringList(ss []string) cty.Value {
	vals := make([]cty.Value, len(ss))
	for i, v := range ss {
		vals[i] = cty.StringVal(v)
	}
	return cty.ListVal(vals)
}

func aptRepositoryModule(in *input) ([]step, string) {
	if in.loop {
		return nil, "loops over repository lines, which the converter can't translate yet; write one task for each"
	}
	in.state("present", "present")
	line := strings.TrimSpace(in.str("repo"))
	if in.problem != "" {
		return nil, in.problem
	}
	m := aptLine.FindStringSubmatch(line)
	if m == nil {
		return nil, fmt.Sprintf("has the repo %q, which isn't a one-line deb source with a URL and suite; deb-src and ppa: stay for a person", line)
	}
	if !in.bool("update_cache", true) || !in.bool("update-cache", true) {
		return nil, "sets update_cache: no; Conn3x always runs apt-get update after writing a repository"
	}
	in.ignore("install_python_apt") // only what Ansible itself needs on the host
	signedBy := ""
	for _, opt := range strings.Fields(m[1]) {
		v, ok := strings.CutPrefix(opt, "signed-by=")
		if !ok {
			return nil, fmt.Sprintf("sets the apt option %q, which a repository step doesn't have", opt)
		}
		signedBy = v
	}
	if !strings.HasPrefix(signedBy, "/") {
		return nil, "doesn't name a key file with signed-by=/path; a repository step trusts one key for this repository only, and the converter can't tell which"
	}
	source, suite, components := m[2], m[3], strings.Fields(m[4])
	flat := strings.HasSuffix(suite, "/")
	if flat != (len(components) == 0) {
		return nil, fmt.Sprintf("has the suite %q with %d components; apt wants components unless the suite ends in /", suite, len(components))
	}
	u, err := url.Parse(source)
	if err != nil {
		return nil, fmt.Sprintf("has the URL %q, which the converter can't read", source)
	}
	key, keyFile, reason := in.repoKey(signedBy)
	if reason != "" {
		return nil, reason
	}
	// The suite and components are in the name so that two sources from one URL get a file each.
	name := slug(strings.Join(append([]string{u.Host + u.Path, suite}, components...), " "))
	if err := (repo.Repo{Name: name, URL: source, Key: key, Suites: []string{suite}, Components: components}).Validate(pkg.Deb); err != nil {
		return nil, "can't be a repository step: " + err.Error()
	}
	attrs := []attr{s("name", name), s("url", source), {key: "key", raw: fmt.Sprintf(`file("${path.module}/%s")`, keyFile)}, {key: "suites", val: stringList([]string{suite})}}
	if len(components) > 0 {
		attrs = append(attrs, attr{key: "components", val: stringList(components)})
	}
	return one("repository", attrs,
		fmt.Sprintf("Check that %s is the key %s holds on the host.", keyFile, signedBy),
		"TODO(convert): Delete the .list file Ansible left in /etc/apt/sources.list.d for this repository, or apt sees it twice.")
}

func yumRepositoryModule(in *input) ([]step, string) {
	if in.loop {
		return nil, "loops over repositories, which the converter can't translate yet; write one task for each"
	}
	in.state("present", "present")
	name := in.str("name")
	if in.problem != "" {
		return nil, in.problem
	}
	urls := in.list("baseurl")
	if len(urls) != 1 {
		return nil, "doesn't set exactly one baseurl; a repository step has one URL, and no metalink or mirrorlist"
	}
	if !in.bool("enabled", true) {
		return nil, "sets enabled: no; Conn3x always enables the repository"
	}
	if !in.bool("gpgcheck", false) {
		return nil, "doesn't set gpgcheck: yes; Conn3x always checks signatures, which Ansible leaves to the host's own setting"
	}
	if in.has("file") && in.str("file") != name {
		return nil, "sets file to something other than name; Conn3x names the .repo file after the repository"
	}
	keys := in.list("gpgkey")
	if len(keys) != 1 {
		return nil, "doesn't set exactly one gpgkey; a repository step has one key"
	}
	key, keyFile, reason := in.repoKey(keys[0])
	if reason != "" {
		return nil, reason
	}
	if err := (repo.Repo{Name: name, URL: urls[0], Key: key}).Validate(pkg.RPM); err != nil {
		return nil, "can't be a repository step: " + err.Error()
	}
	notes := []string{fmt.Sprintf("Check that %s is the key at %s.", keyFile, keys[0])}
	if in.has("description") {
		in.ignore("description")
		notes = append(notes, "description dropped: Conn3x labels the repository with its name.")
	}
	return one("repository", []attr{s("name", name), s("url", urls[0]), {key: "key", raw: fmt.Sprintf(`file("${path.module}/%s")`, keyFile)}}, notes...)
}

func localeGenModule(in *input) ([]step, string) {
	if in.loop {
		return nil, "loops over locales, and a host has one system locale, which a locale step sets"
	}
	in.state("present", "present")
	names := in.list("name")
	if in.problem != "" {
		return nil, in.problem
	}
	if len(names) != 1 {
		return nil, "doesn't name exactly one locale; a locale step also sets the system locale, and a host has one"
	}
	if err := system.ValidateLocale(names[0]); err != nil {
		return nil, "can't be a locale step: " + err.Error()
	}
	return one("locale", []attr{s("name", names[0])},
		fmt.Sprintf("TODO(convert): This step also sets the host's LANG to %s, which locale_gen didn't. To only generate the locale, use a guarded command step instead.", names[0]))
}

// inlineArgs are the options Ansible pulls out of a free-form command line.
var inlineArgs = map[string]bool{"chdir": true, "creates": true, "removes": true, "executable": true, "stdin": true, "stdin_add_newline": true, "strip_empty_ends": true, "warn": true}

func shellQuote(v string) string { return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'" }
