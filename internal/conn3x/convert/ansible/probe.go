// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// A role probes a host and branches on the result:
//
//	- name: Check if PHP is installed.
//	  command: which php
//	  changed_when: false
//	  failed_when: false
//	  register: php_installed
//	- include_tasks: install-from-source.yml
//	  when: php_installed.rc != 0
//
// The probe becomes data "conn3x_command" "php_installed", run on every
// host at plan time, and the when an expression on it, through boolWhen,
// on each task the include reads. steps flattens the role again once its
// probes are known, so the include can read the probe's name.
// A data source reads before any step runs, where Ansible ran the probe
// after the tasks above it; the two agree only when nothing before the
// probe could change what it reads. So a probe becomes that data source
// only when every task before it, in Ansible's run order, is another
// probe, a fact read or a set_fact. A later probe becomes the circuit's
// probe "name" block instead, which reads after every step above it, during
// the apply when one of them has a change pending, and the steps that read
// it test it in only_if, which waits for the apply too. A circuit probe
// hands its exit code over and never fails, so a command probe after
// changes converts only with failed_when: false or ignore_errors: true.
//
// A probe with a when reads every host, as it only reads. Ansible skipped
// it where the when was false, and a later when on its rc, stdout or stat
// there would have stopped the play, so the readers are the same where it
// ran; "is failed" and "is succeeded" aren't, as a skipped task is
// succeeded, and stay.
//
// A stat probe, stat: path=X with register, converts the same way, to
// [ -e X ] || [ -L X ]: stat doesn't follow a link by default, so a
// dangling one still exists. Only X.stat.exists reads it, bare, through
// | bool, compared to true or false, or tested is true; a when on any
// other field stays, naming the field. data "conn3x_file" would read the
// file itself into state, and fail on a directory, a big file or one the
// login user can't read, where stat only reads metadata.

// probe is a converted probe: mayFail says it set failed_when: false, so
// Ansible never marked it failed and "is failed" was always false.
type probe struct {
	mayFail, stat bool
	// late is a probe after tasks that change the host: the circuit's
	// probe block, running cmd, which its readers test in only_if.
	late    bool
	guarded bool // the task has a when
	cmd     string
	// shadowedBy is a later task registering the same name: a when after
	// it reads that task's result, not this probe's. passed is set once
	// steps has reached it.
	shadowedBy *yaml.Node
	passed     bool
}

// stale reports whether a when read now would read a later task's result
// under a converted probe's name.
func (r *role) stale(name string) bool {
	return r.probes[name].passed
}

// probeKeys are what a probe may set besides its command.
var probeKeys = map[string]bool{"name": true, "tags": true, "register": true, "changed_when": true, "check_mode": true, "failed_when": true, "ignore_errors": true}

// readOnlyModules change nothing on the host.
var readOnlyModules = map[string]bool{"set_fact": true, "include_vars": true, "setup": true, "gather_facts": true, "stat": true, "slurp": true, "debug": true, "assert": true, "getent": true, "find": true, "package_facts": true, "service_facts": true}

// probeShaped reports whether a task is a command with register and
// changed_when: false, or a stat with register, whatever else it sets.
func probeShaped(t map[string]*yaml.Node) bool {
	mod, _ := moduleOf(t)
	b, ok := yamlBool(t["changed_when"])
	return t["register"] != nil && (mod == "stat" || mod == "command" && ok && !b)
}

// readOnly reports whether a task leaves the host as it found it, so a
// probe after it reads what Ansible's would have.
func (c *converter) readOnly(t taskAt) bool {
	if t.reason != "" {
		return false
	}
	if _, ok := c.role.defaultTask(t.file, t.node); ok || c.role.isFamilyInclude(t.node, t.file) {
		return true
	}
	m := mapping(t.node)
	mod, _ := moduleOf(m)
	if mod == "command" || mod == "shell" {
		b, ok := yamlBool(m["changed_when"])
		return ok && !b
	}
	return readOnlyModules[mod]
}

// findProbes walks a role's tasks in run order and converts each probe
// that only reads precede, recording for task why the others stay.
func (c *converter) findProbes(tasks []taskAt, vars map[string]string) {
	c.probeWhy = map[*yaml.Node]string{}
	if c.role == nil {
		return
	}
	clean := true
	for _, t := range tasks {
		m := mapping(t.node)
		if p := c.role.probes[scalar(m["register"])]; p != nil && p.shadowedBy == nil {
			p.shadowedBy = t.node
		}
		if t.reason == "" && probeShaped(m) && !c.hidesValues(t.node) && !neverTagged(m["tags"]) {
			why := "probes the host after tasks that change it inside a block with rescue or always, where a circuit has no place for a probe"
			if clean || t.kind == "" && t.group == nil {
				why = c.probe(t, m, vars, !clean)
			}
			c.probeWhy[t.node] = why
		}
		clean = clean && c.readOnly(t)
	}
}

// probe converts one probe into a data source, appended to the role's
// probeBlocks, or, late, into the circuit's probe block, or says why it
// can't.
func (c *converter) probe(t taskAt, m map[string]*yaml.Node, vars map[string]string, late bool) string {
	for _, k := range sortedKeys(m) {
		switch {
		case k == "when":
		case keywords[k] && !probeKeys[k] || strings.HasPrefix(k, "with_"):
			return "sets " + k + " on a probe, which the converter can't carry to a data source yet"
		}
	}
	if n := m["failed_when"]; n != nil {
		if b, ok := yamlBool(n); !ok || b {
			return "uses a failed_when other than false, which the converter can't translate yet"
		}
	}
	if n := m["ignore_errors"]; n != nil {
		if b, ok := yamlBool(n); !ok || !b {
			return "sets ignore_errors to something other than true, which the converter can't translate yet"
		}
	}
	mod, args := moduleOf(m)
	quiet := mod == "stat" || m["failed_when"] != nil || m["ignore_errors"] != nil
	switch {
	case late && !quiet:
		return "probes the host after tasks that change it, and Ansible stops the play when it exits non-zero, where a circuit probe hands the exit code to the steps that read it; add failed_when: false if the exit code is the answer"
	case m["when"] != nil && !quiet:
		return "has a when, and Ansible stops the play when it exits non-zero, which a data source reading every host would do where the when is false; add failed_when: false if the exit code is the answer"
	}
	name := scalar(m["register"])
	if !identifier.MatchString(name) || late && strings.Contains(name, "__") {
		return fmt.Sprintf("registers %q, which isn't a name a data source can have", name)
	}
	if c.role.probes[name] != nil {
		return fmt.Sprintf("registers %s, which an earlier probe already registers, so the two would be one data source", name)
	}
	if len(c.familyNames(args, vars)) > 0 {
		what := "command"
		if mod == "stat" {
			what = "path"
		}
		return "reads a value from vars/<family>.yml in its " + what + ", which the converter can't put in a probe yet"
	}
	in := c.input(mod, args, vars, nil)
	var cmd, why string
	if mod == "stat" {
		cmd, why = statLine(in)
	} else {
		cmd, why = commandLine(in)
	}
	if why == "" {
		why = in.problem
	}
	if extra := in.unused(); why == "" && len(extra) > 0 {
		why = "sets " + strings.Join(extra, ", ") + ", which the converter can't translate yet"
	}
	if why != "" {
		return why
	}
	p := &probe{mayFail: m["failed_when"] != nil, stat: mod == "stat", late: late, guarded: m["when"] != nil, cmd: cmd}
	c.role.probes[name] = p
	if late {
		return ""
	}
	// Ansible stops the play on a non-zero exit unless the task says
	// otherwise; the data source doesn't, so a postcondition does.
	// A stat probe's test exits 1 for a missing path, which isn't a failure.
	post := ""
	if mod == "command" && m["failed_when"] == nil && m["ignore_errors"] == nil {
		post = fmt.Sprintf(`
  lifecycle {
    postcondition {
      condition     = self.exit_code == 0
      error_message = "%s exited ${self.exit_code} on host ${each.key}, where Ansible would have stopped the play."
    }
  }
`, name)
	}
	c.role.probeBlocks = append(c.role.probeBlocks, fmt.Sprintf(`
# Task %q (%s line %d) probes each host at plan time,
# as Ansible ran it before any task had changed the host. The steps whose
# when read %s test its result.
data "conn3x_command" %q {
  for_each = var.hosts
  command  = "%s"

  ssh {
    host             = try(each.value.address, each.value)
    port             = try(each.value.port, var.ssh_port)
    user             = try(each.value.user, var.ssh_user)
    host_key         = try(each.value.host_key, null)
    container        = try(each.value.container, null)
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }
%s}
`, scalar(m["name"]), t.file, t.node.Line, name, name, quoted(cmd), post))
	return ""
}

// statLine is a stat probe's test of its path. stat with follow: true
// would test the link's target, and a path starting with ~ Ansible expands,
// so both stay.
func statLine(in *input) (string, string) {
	path := in.str("path", "dest", "name")
	switch {
	case path == "":
		return "", "has no path"
	case strings.HasPrefix(path, "~"):
		return "", "sets a path starting with ~, which Ansible expands to a home directory and a quoted path in a shell test doesn't"
	case in.bool("follow", false):
		return "", "sets follow: true, which tests where a link points, and the converter only tests whether the path itself exists"
	}
	// These only skip work stat would do on the file; none changes exists.
	for _, k := range []string{"get_attributes", "get_checksum", "get_mime"} {
		if !in.has(k) {
			continue
		}
		if b, ok := yamlBool(in.args[k]); !ok || b {
			return "", "sets " + k + " to something other than false, which the converter can't translate yet"
		}
		in.ignore(k)
	}
	q := shellQuote(path)
	return "[ -e " + q + " ] || [ -L " + q + " ]", ""
}

var (
	probeName   = `([A-Za-z_][A-Za-z0-9_]*)`
	probeLit    = `(?:'([^'\\]*)'|"([^"\\]*)")`
	probeRC     = regexp.MustCompile(`^` + probeName + `\.rc (==|!=) ([0-9]+)$`)
	probeStatus = regexp.MustCompile(`^` + probeName + ` is (succeeded|success|failed|failure)$`)
	probeOut    = regexp.MustCompile(`^` + probeName + `\.stdout (==|!=) ` + probeLit + `$`)
	probeIn     = regexp.MustCompile(`^` + probeLit + ` (in|not in) ` + probeName + `\.stdout$`)
	// Jinja reads true and True alike, and | bool on a bool is the bool.
	probeExists = regexp.MustCompile(`^` + probeName + `\.stat\.exists(?: ?\| ?bool| ?(==|!=) ?(true|True|false|False)| is (not )?(true|false))?$`)
	statField   = regexp.MustCompile(`\b` + probeName + `\.stat\.([A-Za-z_]+)`)
)

// statWhy says why a when on a stat probe's result stays: it reads a field
// other than exists, which the probe's test doesn't return. "" otherwise.
func (r *role) statWhy(n *yaml.Node) string {
	for _, m := range statField.FindAllStringSubmatch(nodeText(n), -1) {
		if p := r.probes[m[1]]; p != nil && p.stat && m[2] != "exists" {
			return fmt.Sprintf("reads %s.stat.%s, and the converted stat probe only tests whether the path exists; test %s yourself in a data \"conn3x_command\"", m[1], m[2], m[2])
		}
	}
	return ""
}

// probeWhen is a when on a converted probe's result as an expression on
// its data source for the step's host: X.rc == 0, X is failed, X.stdout ==
// 'text' or 'text' in X.stdout. Ansible strips the trailing newlines from
// stdout, so chomp does here. "" for anything else, and for "is failed" or
// "is succeeded" on a probe with failed_when: false, which Ansible never
// marked failed, whatever its exit code.
func (r *role) probeWhen(cond string) string {
	ref := func(name string) string {
		if r.probes[name] == nil || r.probes[name].stat || r.stale(name) {
			return ""
		}
		return r.probeRef(name)
	}
	if m := probeExists.FindStringSubmatch(cond); m != nil && r.probes[m[1]] != nil && r.probes[m[1]].stat && !r.stale(m[1]) {
		want := (m[2] == "!=") == strings.EqualFold(m[3], "false")
		if m[5] != "" {
			want = (m[4] == "") == (m[5] == "true")
		}
		op := "=="
		if !want {
			op = "!="
		}
		return fmt.Sprintf("%s.exit_code %s 0", r.probeRef(m[1]), op)
	}
	if m := probeRC.FindStringSubmatch(cond); m != nil {
		if d := ref(m[1]); d != "" {
			return fmt.Sprintf("%s.exit_code %s %s", d, m[2], m[3])
		}
	}
	if m := probeStatus.FindStringSubmatch(cond); m != nil {
		if d := ref(m[1]); d != "" && !r.probes[m[1]].mayFail && !r.probes[m[1]].guarded {
			op := "=="
			if strings.HasPrefix(m[2], "fail") {
				op = "!="
			}
			return fmt.Sprintf("%s.exit_code %s 0", d, op)
		}
	}
	// stdout is sensitive, and a when can't be: nonsensitive lets out only
	// the true or false.
	if m := probeOut.FindStringSubmatch(cond); m != nil {
		if d := ref(m[1]); d != "" {
			return fmt.Sprintf("nonsensitive(chomp(%s.stdout) %s \"%s\")", d, m[2], quoted(m[3]+m[4]))
		}
	}
	if m := probeIn.FindStringSubmatch(cond); m != nil {
		if d := ref(m[4]); d != "" {
			not := ""
			if m[3] == "not in" {
				not = "!"
			}
			return fmt.Sprintf("%snonsensitive(strcontains(%s.stdout, \"%s\"))", not, d, quoted(m[1]+m[2]))
		}
	}
	return ""
}

// probeRef is a converted probe's data source for the step's host: a late
// one is the circuit's probe block, lowered to <circuit>__<name>.
func (r *role) probeRef(name string) string {
	if r.probes[name].late {
		return fmt.Sprintf("data.conn3x_command.%s__%s[each.key]", r.circuit, name)
	}
	return fmt.Sprintf("data.conn3x_command.%s[each.key]", name)
}

// lateRef reports whether a converted when reads a late probe, which only
// the apply may know.
func (r *role) lateRef(expr string) bool {
	return strings.Contains(expr, "data.conn3x_command."+r.circuit+"__")
}

var changedRe = regexp.MustCompile(`^` + probeName + `(?: is changed|\.changed(?: ?\| ?bool)?)$`)

// applyTimeWhen takes out of a role task's when the conditions only the
// apply answers, ANDed at the top: one on a late probe goes to only_if, and
// R is changed, for a task whose register only that reads, becomes
// triggers on R's step's revision, which changes exactly when that step
// changes the host. Only a command step has triggers. The rest stays in t's
// when for the step's when. why is set when R is changed can't convert.
func (c *converter) applyTimeWhen(t map[string]*yaml.Node) (onlyIf, triggers, why string) {
	w := deref(t["when"])
	if c.role == nil || w == nil {
		return "", "", ""
	}
	conds := []*yaml.Node{w}
	if w.Kind == yaml.SequenceNode {
		conds = w.Content
	}
	mod, _ := moduleOf(t)
	var kept []*yaml.Node
	var gates, trig []string
	for _, cn := range conds {
		if cn.Kind != yaml.ScalarNode {
			kept = append(kept, cn)
			continue
		}
		for _, p := range splitTop(strings.Join(strings.Fields(cn.Value), " "), " and ") {
			p = strings.TrimSpace(p)
			if m := changedRe.FindStringSubmatch(p); m != nil && c.changedOnly[m[1]] {
				rev, ok := c.role.changedStep[m[1]]
				switch {
				case mod != "command" && mod != "shell":
					return "", "", fmt.Sprintf("reads whether %s changed, which a circuit follows only in a command step's triggers, on that step's revision; for a restart or reload, notify a handler from the task that registers %s", m[1], m[1])
				case !ok:
					return "", "", fmt.Sprintf("reads whether %s changed, and the task that registers it didn't become one step on every host, whose revision triggers could read", m[1])
				}
				trig = append(trig, rev)
				continue
			}
			if e := c.role.whenExpr(&yaml.Node{Kind: yaml.ScalarNode, Value: p}); e != "" && c.role.lateRef(e) {
				gates = append(gates, e)
				continue
			}
			kept = append(kept, &yaml.Node{Kind: yaml.ScalarNode, Value: p, Line: cn.Line, Column: cn.Column})
		}
	}
	if len(gates) == 0 && len(trig) == 0 {
		return "", "", ""
	}
	switch len(kept) {
	case 0:
		delete(t, "when")
	case 1:
		t["when"] = kept[0]
	default:
		t["when"] = &yaml.Node{Kind: yaml.SequenceNode, Content: kept}
	}
	if len(gates) > 0 {
		onlyIf = andAll(gates)
	}
	return onlyIf, strings.Join(trig, ", "), ""
}
