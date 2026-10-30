// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package ansible converts Ansible playbooks into Conn3x circuits. It only
// translates what it can show means the same thing; every other task is
// kept, commented out, beside the reason, for a person to finish.
package ansible

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"
)

// Issue is a task the converter left for a person to review.
type Issue struct {
	Task   string
	Line   int
	Reason string
}

// Result is a converted playbook.
type Result struct {
	HCL       []byte // the circuits, as a .tf file meant to sit beside the playbook
	Converted int    // tasks translated in full
	Review    []Issue
}

// Options change how a playbook converts.
type Options struct {
	// Inventory, when set, fills in each play's hosts and login instead of
	// leaving variables for them.
	Inventory *Inventory
}

// Convert reads the playbook at path and translates it.
func Convert(path string) (Result, error) { return ConvertWith(path, Options{}) }

// ConvertWith is Convert with options.
func ConvertWith(path string, opts Options) (Result, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return Result{}, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return Result{}, fmt.Errorf("%s: %w", path, err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.SequenceNode {
		return Result{}, fmt.Errorf("%s: a playbook is a list of plays", path)
	}
	c := &converter{dir: filepath.Dir(path), file: filepath.Base(path), inv: opts.Inventory}
	return c.run(doc.Content[0]), nil
}

type converter struct {
	dir, file string
	inv       *Inventory
	res       Result
	hostVars  map[string]bool // groups that still need a hosts variable
	needUser  bool
}

func (c *converter) run(plays *yaml.Node) Result {
	f := hclwrite.NewEmptyFile()
	body := f.Body()
	comment(body, fmt.Sprintf("Converted from %s by conn3x convert ansible.", c.file))
	comment(body, "Search for TODO(convert) to find what still needs a person.")
	body.AppendNewline()

	c.hostVars = map[string]bool{}
	var circuits []*hclwrite.Block
	used := map[string]int{}
	for i, play := range plays.Content {
		p := mapping(play)
		hosts := scalar(p["hosts"])
		name := slug(firstNonEmpty(scalar(p["name"]), hosts, fmt.Sprintf("play_%d", i+1)))
		name = unique(name, used)
		circuits = append(circuits, c.play(name, hosts, p, play))
	}

	groups := make([]string, 0, len(c.hostVars))
	for g := range c.hostVars {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	for _, g := range groups {
		v := body.AppendNewBlock("variable", []string{hostsVar(g)})
		v.Body().SetAttributeRaw("type", rawTokens("map(string)"))
		v.Body().SetAttributeValue("description", cty.StringVal(fmt.Sprintf("Hosts in the Ansible group %q, as name = address.", g)))
		body.AppendNewline()
	}
	loginVars := []struct{ name, desc string }{{"ssh_private_key_file", "Private key Conn3x logs in with."}}
	if c.needUser {
		loginVars = append([]struct{ name, desc string }{{"ssh_user", "User Conn3x logs in as."}}, loginVars...)
	}
	for _, v := range loginVars {
		b := body.AppendNewBlock("variable", []string{v.name})
		b.Body().SetAttributeRaw("type", rawTokens("string"))
		b.Body().SetAttributeValue("description", cty.StringVal(v.desc))
		body.AppendNewline()
	}
	for i, b := range circuits {
		body.AppendBlock(b)
		if i < len(circuits)-1 {
			body.AppendNewline()
		}
	}
	c.res.HCL = hclwrite.Format(f.Bytes())
	return c.res
}

func hostsVar(group string) string { return slug(group) + "_hosts" }

// login sets the ssh user and port from the inventory when every host in the
// group agrees on them, and otherwise leaves a variable.
func (c *converter) login(circuit, ssh *hclwrite.Body, play string, node *yaml.Node, g *Group) {
	if g == nil {
		c.needUser = true
		ssh.SetAttributeRaw("user", rawTokens("var.ssh_user"))
		return
	}
	for _, key := range []string{"ansible_user", "ansible_port"} {
		// Mixed when hosts set different values, or only some set one.
		if _, same := g.Common(key); !same && len(g.Values(key)) > 0 {
			vals := g.Values(key)
			if len(vals) == 1 {
				vals = append(vals, "the default")
			}
			c.playIssue(circuit, play, node, fmt.Sprintf("has hosts with different %s (%s); a circuit logs in to all its hosts the same way, so split them into one circuit each", key, strings.Join(vals, ", ")))
		}
	}
	if user, ok := g.Common("ansible_user"); ok {
		ssh.SetAttributeValue("user", cty.StringVal(user))
	} else {
		c.needUser = true
		ssh.SetAttributeRaw("user", rawTokens("var.ssh_user"))
	}
	if port, ok := g.Common("ansible_port"); ok && digits.MatchString(port) {
		ssh.SetAttributeRaw("port", rawTokens(port))
	}
}

// play turns one play into a circuit.
func (c *converter) play(name, hosts string, p map[string]*yaml.Node, node *yaml.Node) *hclwrite.Block {
	circuit := hclwrite.NewBlock("circuit", []string{name})
	cb := circuit.Body()
	var group *Group
	if c.inv != nil {
		group = c.inv.Group(hosts)
	}
	if group != nil && len(group.hosts) > 0 {
		addrs := map[string]cty.Value{}
		for h, a := range group.Addresses() {
			addrs[h] = cty.StringVal(a)
		}
		cb.SetAttributeValue("hosts", cty.ObjectVal(addrs))
	} else {
		if c.inv != nil {
			c.playIssue(cb, name, node, fmt.Sprintf("targets %q, which the inventory doesn't define as a group; set var.%s", hosts, hostsVar(hosts)))
		}
		c.hostVars[hosts] = true
		cb.SetAttributeRaw("hosts", rawTokens("var."+hostsVar(hosts)))
	}
	cb.AppendNewline()
	ssh := cb.AppendNewBlock("ssh", nil).Body()
	c.login(cb, ssh, name, node, group)
	ssh.SetAttributeRaw("private_key_file", rawTokens("var.ssh_private_key_file"))
	become := truthy(scalar(p["become"]))
	if become {
		ssh.SetAttributeValue("become", cty.True)
	}

	vars := map[string]string{}
	for k, v := range mapping(p["vars"]) {
		if v.Kind == yaml.ScalarNode {
			vars[k] = v.Value
		}
	}
	if p["roles"] != nil {
		c.issue(cb, name, p["roles"], "uses roles, which the converter can't translate yet; convert each role's tasks and add them as steps")
	}

	// Handlers first, so steps know which notify targets exist.
	handlers := map[string]string{} // Ansible handler name => Conn3x handler name
	var handlerBlocks []*hclwrite.Block
	usedH := map[string]int{}
	for _, h := range seq(p["handlers"]) {
		t := mapping(h)
		hname := scalar(t["name"])
		mod, args := moduleOf(t)
		action := map[string]string{"restarted": "restart", "reloaded": "reload"}[scalar(args["state"])]
		if (mod != "service" && mod != "systemd" && mod != "systemd_service") || action == "" || len(args) != 2 || scalar(args["name"]) == "" {
			c.issue(cb, hname, h, "is a handler that doesn't restart or reload a service; Conn3x handlers do only that")
			continue
		}
		id := unique(slug(hname), usedH)
		handlers[hname] = id
		hb := hclwrite.NewBlock("handler", []string{id})
		svc := hb.Body().AppendNewBlock("service", nil).Body()
		svc.SetAttributeValue("name", cty.StringVal(scalar(args["name"])))
		svc.SetAttributeValue("action", cty.StringVal(action))
		handlerBlocks = append(handlerBlocks, hb)
	}

	used := map[string]int{}
	var tasks []*yaml.Node
	for _, key := range []string{"pre_tasks", "tasks", "post_tasks"} {
		tasks = append(tasks, seq(p[key])...)
	}
	for _, t := range tasks {
		c.task(cb, t, become, vars, handlers, used)
	}
	for _, hb := range handlerBlocks {
		cb.AppendNewline()
		cb.AppendBlock(hb)
	}
	return circuit
}

// keywords are task keys that are not the module.
var keywords = map[string]bool{
	"name": true, "notify": true, "become": true, "become_user": true, "when": true, "loop": true,
	"loop_control": true, "register": true, "tags": true, "ignore_errors": true, "changed_when": true,
	"failed_when": true, "until": true, "retries": true, "delay": true, "delegate_to": true,
	"run_once": true, "args": true, "environment": true, "vars": true, "block": true, "rescue": true,
	"always": true, "no_log": true, "check_mode": true, "diff": true, "listen": true, "become_method": true,
	"become_exe": true, "become_flags": true, "connection": true, "remote_user": true, "port": true,
	"throttle": true, "timeout": true, "async": true, "poll": true, "any_errors_fatal": true,
	"ignore_unreachable": true, "delegate_facts": true, "module_defaults": true, "collections": true,
	"debugger": true, "action": true, "local_action": true,
}

// translatable keywords are handled; the rest stop a task from converting.
var harmless = map[string]bool{"name": true, "notify": true, "args": true, "tags": true, "no_log": true, "become": true}

func (c *converter) task(body *hclwrite.Body, node *yaml.Node, playBecome bool, vars, handlers map[string]string, used map[string]int) {
	t := mapping(node)
	name := scalar(t["name"])
	for k := range t {
		if strings.HasPrefix(k, "with_") {
			c.issue(body, name, node, "uses "+k+", a loop, which the converter can't translate yet")
			return
		}
	}
	var items []string
	if l, ok := t["loop"]; ok {
		var why string
		if items, why = literalLoop(l); why != "" {
			c.issue(body, name, node, why)
			return
		}
	}
	module := ""
	for _, k := range sortedKeys(t) {
		if k == "loop" && items != nil {
			continue
		}
		if keywords[k] && !harmless[k] {
			c.issue(body, name, node, "uses "+k+", which the converter can't translate yet")
			return
		}
		if keywords[k] {
			continue
		}
		// Any key that isn't a keyword is a module, and a task has only one.
		if module != "" {
			c.issue(body, name, node, "has both "+module+" and "+k+", and the converter can't tell which is the module")
			return
		}
		module = k
	}
	if b := t["become"]; b != nil && truthy(scalar(b)) != playBecome {
		c.issue(body, name, node, "sets become differently from its play; give it its own circuit with its own ssh block")
		return
	}
	mod, args := moduleOf(t)
	if mod == "" {
		c.issue(body, name, node, "has no module the converter recognises")
		return
	}
	m, ok := modules[mod]
	if !ok {
		c.issue(body, name, node, "uses the "+mod+" module, which has no Conn3x equivalent yet")
		return
	}
	in := &input{args: args, vars: vars, dir: c.dir, used: map[string]bool{}, loop: items != nil}
	steps, reason := m(in)
	if reason == "" && items != nil {
		reason = loopSteps(steps, in.itemUsed)
	}
	if reason == "" {
		reason = in.problem
	}
	if reason == "" {
		if extra := in.unused(); len(extra) > 0 {
			reason = "sets " + strings.Join(extra, ", ") + ", which the converter can't translate yet"
		}
	}
	if reason != "" {
		c.issue(body, name, node, reason)
		return
	}

	var notify []string
	for _, n := range listOf(t["notify"]) {
		h, ok := handlers[n]
		if !ok {
			c.issue(body, name, node, fmt.Sprintf("notifies %q, which could not be converted", n))
			return
		}
		notify = append(notify, "handler."+h)
	}

	base := slug(firstNonEmpty(name, mod))
	for i, s := range steps {
		stepName := base
		if len(steps) > 1 {
			stepName = base + "_" + slug(s.suffix)
		}
		stepName = unique(stepName, used)
		body.AppendNewline()
		for _, note := range s.notes {
			comment(body, note)
		}
		sb := body.AppendNewBlock("step", []string{stepName}).Body()
		if items != nil {
			vals := make([]cty.Value, len(items))
			for i, it := range items {
				vals[i] = cty.StringVal(it)
			}
			sb.SetAttributeValue("for_each", cty.TupleVal(vals))
		}
		mb := sb.AppendNewBlock(s.module, nil).Body()
		for _, a := range s.attrs {
			if a.raw != "" {
				mb.SetAttributeRaw(a.key, rawTokens(a.raw))
			} else {
				mb.SetAttributeValue(a.key, a.val)
			}
		}
		if len(notify) > 0 && i == len(steps)-1 {
			sb.SetAttributeRaw("notify", rawTokens("["+strings.Join(notify, ", ")+"]"))
		}
	}
	c.res.Converted++
}

var digits = regexp.MustCompile(`^[0-9]+$`)

// playIssue records something about a whole play for review, as a comment
// at the top of its circuit.
func (c *converter) playIssue(body *hclwrite.Body, play string, node *yaml.Node, reason string) {
	c.res.Review = append(c.res.Review, Issue{Task: "play " + play, Line: node.Line, Reason: reason})
	comment(body, fmt.Sprintf("TODO(convert): Play %q (%s line %d) %s.", play, c.file, node.Line, reason))
}

// issue records a task for review and leaves it in the output as comments.
func (c *converter) issue(body *hclwrite.Body, name string, node *yaml.Node, reason string) {
	c.res.Review = append(c.res.Review, Issue{Task: name, Line: node.Line, Reason: reason})
	body.AppendNewline()
	what := "This task"
	if name != "" {
		what = fmt.Sprintf("Task %q", name)
	}
	comment(body, fmt.Sprintf("TODO(convert): %s (%s line %d) %s.", what, c.file, node.Line, reason))
	out, _ := yaml.Marshal([]*yaml.Node{node})
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		comment(body, "  "+line)
	}
}

// moduleOf finds a task's module, without its collection prefix, and its
// arguments, merging free-form text and args:.
func moduleOf(t map[string]*yaml.Node) (string, map[string]*yaml.Node) {
	for _, k := range sortedKeys(t) {
		if keywords[k] || strings.HasPrefix(k, "with_") {
			continue
		}
		mod := k[strings.LastIndex(k, ".")+1:]
		args := map[string]*yaml.Node{}
		switch v := t[k]; v.Kind {
		case yaml.MappingNode:
			args = mapping(v)
		case yaml.ScalarNode:
			if mod == "command" || mod == "shell" {
				args["_raw"] = v
			} else {
				for _, kv := range strings.Fields(v.Value) {
					if key, val, ok := strings.Cut(kv, "="); ok {
						args[key] = &yaml.Node{Kind: yaml.ScalarNode, Value: val, Line: v.Line}
					} else {
						args["_raw"] = v
					}
				}
				// Marks the task as free-form: this split ignores quoting,
				// so a module that needs exact text refuses it.
				args["_raw"] = v
			}
		}
		for ak, av := range mapping(t["args"]) {
			args[ak] = av
		}
		return mod, args
	}
	return "", nil
}

// YAML helpers.

func mapping(n *yaml.Node) map[string]*yaml.Node {
	out := map[string]*yaml.Node{}
	if n == nil || n.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		out[n.Content[i].Value] = n.Content[i+1]
	}
	return out
}

func seq(n *yaml.Node) []*yaml.Node {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	return n.Content
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

// listOf reads a string or a list of strings.
func listOf(n *yaml.Node) []string {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.ScalarNode {
		return []string{n.Value}
	}
	var out []string
	for _, e := range seq(n) {
		out = append(out, scalar(e))
	}
	return out
}

func truthy(s string) bool {
	switch strings.ToLower(s) {
	case "true", "yes", "on", "1", "y":
		return true
	}
	return false
}

func sortedKeys(m map[string]*yaml.Node) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// HCL helpers.

func comment(body *hclwrite.Body, text string) {
	body.AppendUnstructuredTokens(hclwrite.Tokens{
		{Type: hclsyntaxComment, Bytes: []byte("# " + strings.TrimRight(text, " ") + "\n")},
	})
}

func rawTokens(src string) hclwrite.Tokens {
	return hclwrite.Tokens{{Type: hclsyntaxIdent, Bytes: []byte(src)}}
}

var nonIdent = regexp.MustCompile(`[^a-z0-9]+`)

// slug makes a valid identifier with no double underscore.
func slug(s string) string {
	s = strings.Trim(nonIdent.ReplaceAllString(strings.ToLower(s), "_"), "_")
	if s == "" {
		s = "unnamed"
	}
	if s[0] >= '0' && s[0] <= '9' {
		s = "n_" + s
	}
	return s
}

func unique(name string, used map[string]int) string {
	used[name]++
	if n := used[name]; n > 1 {
		return fmt.Sprintf("%s_%d", name, n)
	}
	return name
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
