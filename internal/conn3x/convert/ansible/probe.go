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
// host at plan time, and the when an expression on it, through boolWhen.
// A data source reads before any step runs, where Ansible ran the probe
// after the tasks above it; the two agree only when nothing before the
// probe could change what it reads. So a probe converts only when every
// task before it, in Ansible's run order, is another probe, a fact read or
// a set_fact. Any later probe stays for review, with that reason.

// probe is a converted probe: mayFail says it set failed_when: false, so
// Ansible never marked it failed and "is failed" was always false.
type probe struct {
	mayFail bool
}

// probeKeys are what a probe may set besides its command.
var probeKeys = map[string]bool{"name": true, "tags": true, "register": true, "changed_when": true, "check_mode": true, "failed_when": true, "ignore_errors": true}

// readOnlyModules change nothing on the host.
var readOnlyModules = map[string]bool{"set_fact": true, "include_vars": true, "setup": true, "gather_facts": true, "stat": true, "slurp": true, "debug": true, "assert": true, "getent": true, "find": true, "package_facts": true, "service_facts": true}

// probeShaped reports whether a task is a command with register and
// changed_when: false, whatever else it sets.
func probeShaped(t map[string]*yaml.Node) bool {
	mod, _ := moduleOf(t)
	b, ok := yamlBool(t["changed_when"])
	return mod == "command" && t["register"] != nil && ok && !b
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
		if t.reason == "" && probeShaped(m) && !c.hidesValues(t.node) && !neverTagged(m["tags"]) {
			why := "probes the host after tasks that change it, and a data source reads at plan time, before any step runs, so it would read the host before they do"
			if clean {
				why = c.probe(t, m, vars)
			}
			c.probeWhy[t.node] = why
		}
		clean = clean && c.readOnly(t)
	}
}

// probe converts one probe into a data source, appended to the role's
// probeBlocks, or says why it can't.
func (c *converter) probe(t taskAt, m map[string]*yaml.Node, vars map[string]string) string {
	for _, k := range sortedKeys(m) {
		switch {
		case k == "when":
			return "has a when, which the converter can't put on a probe yet: a data source reads on every host"
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
	name := scalar(m["register"])
	if !identifier.MatchString(name) {
		return fmt.Sprintf("registers %q, which isn't a name a data source can have", name)
	}
	if c.role.probes[name] != nil {
		return fmt.Sprintf("registers %s, which an earlier probe already registers, so the two would be one data source", name)
	}
	_, args := moduleOf(m)
	if len(c.familyNames(args, vars)) > 0 {
		return "reads a value from vars/<family>.yml in its command, which the converter can't put in a probe yet"
	}
	in := c.input("command", args, vars, nil)
	cmd, why := commandLine(in)
	if why == "" {
		why = in.problem
	}
	if extra := in.unused(); why == "" && len(extra) > 0 {
		why = "sets " + strings.Join(extra, ", ") + ", which the converter can't translate yet"
	}
	if why != "" {
		return why
	}
	// Ansible stops the play on a non-zero exit unless the task says
	// otherwise; the data source doesn't, so a postcondition does.
	post := ""
	if m["failed_when"] == nil && m["ignore_errors"] == nil {
		post = fmt.Sprintf(`
  lifecycle {
    postcondition {
      condition     = self.exit_code == 0
      error_message = "%s exited ${self.exit_code} on host ${each.key}, where Ansible would have stopped the play."
    }
  }
`, name)
	}
	c.role.probes[name] = &probe{mayFail: m["failed_when"] != nil}
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

var (
	probeName   = `([A-Za-z_][A-Za-z0-9_]*)`
	probeLit    = `(?:'([^'\\]*)'|"([^"\\]*)")`
	probeRC     = regexp.MustCompile(`^` + probeName + `\.rc (==|!=) ([0-9]+)$`)
	probeStatus = regexp.MustCompile(`^` + probeName + ` is (succeeded|success|failed|failure)$`)
	probeOut    = regexp.MustCompile(`^` + probeName + `\.stdout (==|!=) ` + probeLit + `$`)
	probeIn     = regexp.MustCompile(`^` + probeLit + ` (in|not in) ` + probeName + `\.stdout$`)
)

// probeWhen is a when on a converted probe's result as an expression on
// its data source for the step's host: X.rc == 0, X is failed, X.stdout ==
// 'text' or 'text' in X.stdout. Ansible strips the trailing newlines from
// stdout, so chomp does here. "" for anything else, and for "is failed" or
// "is succeeded" on a probe with failed_when: false, which Ansible never
// marked failed, whatever its exit code.
func (r *role) probeWhen(cond string) string {
	ref := func(name string) string {
		if r.probes[name] == nil {
			return ""
		}
		return fmt.Sprintf("data.conn3x_command.%s[each.key]", name)
	}
	if m := probeRC.FindStringSubmatch(cond); m != nil {
		if d := ref(m[1]); d != "" {
			return fmt.Sprintf("%s.exit_code %s %s", d, m[2], m[3])
		}
	}
	if m := probeStatus.FindStringSubmatch(cond); m != nil {
		if d := ref(m[1]); d != "" && !r.probes[m[1]].mayFail {
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
