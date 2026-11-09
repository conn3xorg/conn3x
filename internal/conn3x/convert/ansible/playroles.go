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
	task   bool // an include_role or import_role, which counts as a task
}

// convertedRole is a role written into the result as a circuit directory.
type convertedRole struct {
	dir  string // the directory in Result.Files, such as circuit-web
	vars map[string]bool
}

// roleCallKeys are what a role call may set besides its name and vars.
var roleCallKeys = map[string]bool{"name": true, "tags": true, "vars": true, "become": true}

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
			b := truthy(scalar(m[k]))
			call.become = &b
		case keywords[k]:
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
		case !keywords[k] || k == "name" || k == "tags":
		case k == "vars":
			for kk, v := range mapping(m[k]) {
				call.vars[kk] = v
			}
		case k == "become":
			b := truthy(scalar(m[k]))
			call.become = &b
		default:
			why = firstNonEmpty(why, "sets "+k+" on "+mod+", which the converter can't translate yet")
		}
	}
	return c.checkCall(call, why)
}

// checkCall returns the call when its role can be converted, and otherwise
// records why for flatten and returns nil.
func (c *converter) checkCall(call *roleCall, why string) *roleCall {
	if why == "" {
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
	if r, ok := c.roles[rel]; ok {
		return r, ""
	}
	if st, err := os.Stat(filepath.Join(c.path(rel), "tasks")); err != nil || !st.IsDir() {
		return nil, fmt.Sprintf("runs the role %s, which isn't at %s beside the playbook; install it there, as with ansible-galaxy role install -p roles, and convert again", name, rel)
	}
	res, err := ConvertRole(c.path(rel))
	if err != nil {
		return nil, fmt.Sprintf("runs the role %s, which can't be converted: %s", name, err)
	}
	base := filepath.Base(rel)
	dir := "circuit-" + strings.ReplaceAll(unique(slug(base[strings.LastIndex(base, ".")+1:]), c.roleDirs), "_", "-")
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
	r := &convertedRole{dir: dir, vars: map[string]bool{}}
	for _, v := range res.Variables {
		r.vars[v] = true
	}
	c.roles[rel] = r
	return r, ""
}

// module writes the block that calls a role's circuit. head is the play's
// first circuit, whose hosts and login the module takes; after is what it
// waits for, if anything.
func (c *converter) module(call *roleCall, head *hclwrite.Body, playVars map[string]*yaml.Node, after string) *hclwrite.Block {
	r, _ := c.convertRole(call.role)
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

// lastStep is the address of a circuit's last step, which every step before
// it runs ahead of, or empty when it has none.
func lastStep(circuit *hclwrite.Block) string {
	addr := ""
	for _, blk := range circuit.Body().Blocks() {
		if blk.Type() != "step" || len(blk.Body().Blocks()) == 0 {
			continue
		}
		for _, inner := range blk.Body().Blocks() {
			if t, ok := configs.CircuitStepType(inner.Type()); ok {
				addr = t + "." + circuit.Labels()[0] + "__" + blk.Labels()[0]
			}
		}
	}
	return addr
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
