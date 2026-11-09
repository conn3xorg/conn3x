// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"

	"github.com/opentofu/opentofu/internal/configs"
)

// A play's roles, and the include_role and import_role tasks at the top of
// its task lists, each become a module block calling the role converted
// into its own circuit directory. Ansible runs a play's parts in order, so
// the play splits around each call into circuits and modules that each
// wait for the one before.

// segment is a run of tasks, or one role call.
type segment struct {
	tasks []*yaml.Node
	call  *roleCall
}

// roleCall is a role a play runs, with what it passes in.
type roleCall struct {
	node   *yaml.Node
	role   string
	vars   map[string]*yaml.Node
	become *bool
	task   bool   // an include_role or import_role, which counts as a task
	file   string // where the call is written, when not the playbook: a role's meta/
}

// convertedRole is a role written into the result as a circuit directory.
type convertedRole struct {
	dir  string // the directory in Result.Files, such as circuit-web
	vars map[string]bool
	deps []*roleCall // its meta/ dependencies, which run before it
	// again is meta/'s allow_duplicates: the role runs each time it's
	// listed, not once a play.
	again bool
	// from and converted are where its tasks are, relative to the
	// playbook, and how many converted, to take them back out of the
	// result when nothing calls it.
	from      string
	converted int
}

// includeRoleOptions are include_role's own arguments, which a roles entry
// would pass to the role as variables instead; refused either way.
var includeRoleOptions = map[string]bool{
	"tasks_from": true, "vars_from": true, "defaults_from": true, "handlers_from": true,
	"apply": true, "public": true, "allow_duplicates": true, "rolespec_validate": true,
}

// setBecome reads a call's become, which must be a plain true or false:
// anything else, such as a Jinja expression, would be read as false.
func (call *roleCall) setBecome(n *yaml.Node) string {
	switch strings.ToLower(scalar(n)) {
	case "true", "yes", "on":
		b := true
		call.become = &b
	case "false", "no", "off":
		b := false
		call.become = &b
	default:
		return "sets become to something other than true or false, which the converter can't translate"
	}
	return ""
}

// segments splits a play's tasks around the roles it runs, in the order
// Ansible runs them: pre_tasks, roles, tasks, post_tasks. A call that can't
// convert stays among the tasks, and flatten leaves it for review.
func (c *converter) segments(p map[string]*yaml.Node) []segment {
	var segs []segment
	var tasks []*yaml.Node
	add := func(n *yaml.Node, call *roleCall) {
		if call == nil {
			tasks = append(tasks, n)
			return
		}
		if len(tasks) > 0 {
			segs = append(segs, segment{tasks: tasks})
			tasks = nil
		}
		segs = append(segs, segment{call: call})
	}
	for _, key := range []string{"pre_tasks", "roles", "tasks", "post_tasks"} {
		for _, n := range seq(p[key]) {
			if key == "roles" {
				add(n, c.playRole(n))
				continue
			}
			mod, args := moduleOf(mapping(n))
			if mod != "include_role" && mod != "import_role" {
				add(n, nil)
				continue
			}
			add(n, c.includeRole(n, mod, args))
		}
	}
	if len(tasks) > 0 || len(segs) == 0 {
		segs = append(segs, segment{tasks: tasks})
	}
	return segs
}

// playRole reads an entry of a play's roles list.
func (c *converter) playRole(n *yaml.Node) *roleCall {
	call := &roleCall{node: n, vars: map[string]*yaml.Node{}}
	if n.Kind == yaml.ScalarNode {
		call.role = n.Value
		return c.checkCall(call, "")
	}
	m := mapping(n)
	call.role = firstNonEmpty(scalar(m["role"]), scalar(m["name"]))
	why := ""
	for _, k := range sortedKeys(m) {
		switch {
		case k == "role" || k == "name" || k == "tags":
		case k == "vars":
			for kk, v := range mapping(m[k]) {
				call.vars[kk] = v
			}
		case k == "become":
			why = firstNonEmpty(why, call.setBecome(m[k]))
		case keywords[k] || includeRoleOptions[k]:
			why = firstNonEmpty(why, "sets "+k+" on the role, which the converter can't translate yet")
		default:
			// The older way to pass a role its variables.
			call.vars[k] = m[k]
		}
	}
	return c.checkCall(call, why)
}

// includeRole reads an include_role or import_role task.
func (c *converter) includeRole(n *yaml.Node, mod string, args map[string]*yaml.Node) *roleCall {
	call := &roleCall{node: n, role: scalar(args["name"]), vars: map[string]*yaml.Node{}, task: true}
	why := ""
	for _, k := range sortedKeys(args) {
		if k != "name" {
			why = firstNonEmpty(why, "sets "+k+" on "+mod+", which the converter can't translate yet")
		}
	}
	m := mapping(n)
	for _, k := range sortedKeys(m) {
		switch {
		case k == "name" || k == "tags" || k[strings.LastIndex(k, ".")+1:] == mod && !keywords[k]:
		case k == "vars":
			for kk, v := range mapping(m[k]) {
				call.vars[kk] = v
			}
		case k == "become":
			why = firstNonEmpty(why, call.setBecome(m[k]))
		default:
			why = firstNonEmpty(why, "sets "+k+" on "+mod+", which the converter can't translate yet")
		}
	}
	return c.checkCall(call, why)
}

// checkCall returns the call when its role can be converted, and otherwise
// records why for flatten and returns nil.
func (c *converter) checkCall(call *roleCall, why string) *roleCall {
	switch {
	case why != "":
	case c.playNoLog:
		why = "runs a role in a play that sets no_log, which its circuit wouldn't keep; convert the role with -role and check what it writes before calling it"
	case c.otherUser != "":
		why = "runs a role in a play where " + c.otherUser + ", which its circuit wouldn't keep; convert the role with -role and set who it runs as"
	default:
		_, why = c.convertRole(call.role)
	}
	if why != "" {
		c.callWhy[call.node] = why
		return nil
	}
	return call
}

// convertRole converts the named role once, into Result.Files, and returns
// it, or why it can't.
func (c *converter) convertRole(name string) (*convertedRole, string) {
	switch {
	case name == "":
		return nil, "runs a role without naming it"
	case strings.Contains(name, "{{") || strings.Contains(name, "{%"):
		return nil, "names its role with a Jinja expression, which the converter can't translate"
	}
	rel := filepath.Join("roles", name)
	if strings.Contains(name, "/") {
		rel = filepath.Clean(name)
	}
	isRole := func(rel string) bool {
		st, err := os.Stat(filepath.Join(c.path(rel), "tasks"))
		return err == nil && st.IsDir()
	}
	// After roles/, Ansible looks beside the playbook itself.
	if !strings.Contains(name, "/") && !isRole(rel) && isRole(name) {
		rel = name
	}
	if r, ok := c.roles[rel]; ok {
		return r, ""
	}
	if !isRole(rel) {
		return nil, fmt.Sprintf("runs the role %s, which isn't at %s beside the playbook; install it there, as with ansible-galaxy role install -p roles, and convert again", name, rel)
	}
	if c.converting[rel] {
		return nil, fmt.Sprintf("runs the role %s, which depends on itself through meta/ dependencies", name)
	}
	c.converting[rel] = true
	defer delete(c.converting, rel)
	// Dependencies read like entries of a play's roles list.
	meta, metaFile := (&converter{dir: c.path(rel)}).main(hclwrite.NewEmptyFile().Body(), "meta")
	var deps []*roleCall
	for _, d := range seq(mapping(meta)["dependencies"]) {
		dep := c.playRole(d)
		if dep == nil {
			return nil, fmt.Sprintf("runs the role %s, whose dependency can't convert: it %s", name, c.callWhy[d])
		}
		dep.file = filepath.ToSlash(filepath.Join(rel, metaFile))
		deps = append(deps, dep)
	}
	res, err := convertRoleDir(c.path(rel), true)
	if err != nil {
		return nil, fmt.Sprintf("runs the role %s, which can't be converted: %s", name, err)
	}
	base := filepath.Base(rel)
	dir := unique("circuit-"+strings.ReplaceAll(slug(base[strings.LastIndex(base, ".")+1:]), "_", "-"), c.roleDirs)
	if c.res.Files == nil {
		c.res.Files = map[string][]byte{}
	}
	for p, b := range res.Files {
		c.res.Files[dir+"/"+p] = b
	}
	from := filepath.ToSlash(rel) + "/"
	for _, r := range res.Review {
		r.File = from + r.File
		c.res.Review = append(c.res.Review, r)
	}
	for _, r := range res.Notes {
		r.File = from + r.File
		c.res.Notes = append(c.res.Notes, r)
	}
	c.res.Converted += res.Converted
	r := &convertedRole{dir: dir, vars: map[string]bool{}, deps: deps, again: truthy(scalar(mapping(meta)["allow_duplicates"])),
		from: from, converted: res.Converted}
	for _, v := range res.Variables {
		r.vars[v] = true
	}
	c.roles[rel] = r
	return r, ""
}

// calls writes the blocks that call a role's circuit and, before it, its
// dependencies', each waiting for the one before, starting after after. It
// returns what the next part waits for. A role from a roles list or meta/
// that the play already ran, with the same vars, runs once, as in Ansible;
// an include_role always runs.
func (c *converter) calls(call *roleCall, head *hclwrite.Body, playVars map[string]*yaml.Node, after string) ([]*hclwrite.Block, string) {
	r, _ := c.convertRole(call.role)
	if !call.task && !r.again {
		key := r.dir + " " + callKey(call)
		if c.ran[key] {
			return nil, after
		}
		c.ran[key] = true
	}
	var blocks []*hclwrite.Block
	for _, dep := range r.deps {
		b, a := c.calls(dep, head, playVars, after)
		blocks, after = append(blocks, b...), a
	}
	mb := c.module(call, head, playVars, after)
	return append(blocks, mb), "module." + mb.Labels()[0]
}

// callKey is what a role call passes, so two calls that pass the same count
// as one.
func callKey(call *roleCall) string {
	keys := make([]string, 0, len(call.vars))
	for k, v := range call.vars {
		b, _ := yaml.Marshal(v)
		keys = append(keys, fmt.Sprintf("%q=%q", k, b))
	}
	sort.Strings(keys)
	if call.become != nil {
		keys = append(keys, fmt.Sprint("become=", *call.become))
	}
	return strings.Join(keys, " ")
}

// module writes the block that calls a role's circuit. head is the play's
// first circuit, whose hosts and login the module takes; after is what it
// waits for, if anything.
func (c *converter) module(call *roleCall, head *hclwrite.Body, playVars map[string]*yaml.Node, after string) *hclwrite.Block {
	r, _ := c.convertRole(call.role)
	c.called[r.dir] = true
	if call.file != "" {
		file := c.file
		c.file = call.file
		defer func() { c.file = file }()
	}
	base := filepath.Base(call.role)
	name := unique(slug(base[strings.LastIndex(base, ".")+1:]), c.modules)
	mb := hclwrite.NewBlock("module", []string{name})
	b := mb.Body()
	b.SetAttributeValue("source", cty.StringVal("./"+r.dir))
	b.AppendNewline()
	b.SetAttributeRaw("hosts", head.GetAttribute("hosts").Expr().BuildTokens(nil))
	var ssh *hclwrite.Body
	for _, blk := range head.Blocks() {
		if blk.Type() == "ssh" {
			ssh = blk.Body()
		}
	}
	for _, k := range []string{"user", "port", "private_key_file", "known_hosts_file", "become"} {
		if k == "become" && call.become != nil {
			b.SetAttributeValue("ssh_become", cty.BoolVal(*call.become))
			continue
		}
		if a := ssh.GetAttribute(k); a != nil {
			b.SetAttributeRaw("ssh_"+k, a.Expr().BuildTokens(nil))
		}
	}

	// A role sees the play's vars over its own defaults, and what the call
	// passes over both.
	what := firstNonEmpty(scalar(mapping(call.node)["name"]), "role "+call.role)
	vals := map[string]*yaml.Node{}
	for k, v := range playVars {
		if r.vars[k] {
			vals[k] = v
		}
	}
	for k, v := range call.vars {
		if !r.vars[k] {
			c.issue(b, what, call.node, fmt.Sprintf("passes %s, which %s has no variable for, because the role fixes it in vars/ or its default isn't a plain value; set it in the circuit by hand", k, r.dir))
			continue
		}
		vals[k] = v
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		b.AppendNewline()
	}
	for _, k := range keys {
		v, number, why := plainValue(vals[k])
		switch {
		case why != "":
			c.issue(b, what, vals[k], fmt.Sprintf("sets %s to %s, which the converter can't carry over yet", k, why))
		case number:
			b.SetAttributeRaw(k, rawTokens(v))
		default:
			b.SetAttributeValue(k, cty.StringVal(v))
		}
	}
	if after != "" {
		b.AppendNewline()
		b.SetAttributeRaw("depends_on", rawTokens("["+after+"]"))
	}
	if call.task {
		c.res.Converted++
	}
	return mb
}

// finished is what to wait for so a circuit is done: its last step, which
// every step before it runs ahead of, and its handlers, which Ansible runs
// before the play's next section. Empty when it has no steps.
func finished(circuit *hclwrite.Block) string {
	name := circuit.Labels()[0]
	last := ""
	var handlers []string
	for _, blk := range circuit.Body().Blocks() {
		switch blk.Type() {
		case "step":
			for _, inner := range blk.Body().Blocks() {
				if t, ok := configs.CircuitStepType(inner.Type()); ok {
					last = t + "." + name + "__" + blk.Labels()[0]
				}
			}
		case "handler":
			handlers = append(handlers, "conn3x_service_action."+name+"__"+blk.Labels()[0])
		}
	}
	if last == "" {
		return ""
	}
	return strings.Join(append([]string{last}, handlers...), ", ")
}

// waitFor makes a circuit's first step wait for addr, so the circuit runs
// after it.
func waitFor(circuit *hclwrite.Block, addr string) {
	for _, blk := range circuit.Body().Blocks() {
		if blk.Type() == "step" {
			blk.Body().SetAttributeRaw("depends_on", rawTokens("["+addr+"]"))
			return
		}
	}
}
