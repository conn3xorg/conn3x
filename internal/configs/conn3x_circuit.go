// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/addrs"
)

// Circuits are Conn3x's playbooks. A circuit names a set of hosts and an
// ordered list of steps; each step uses one host module. Rather than adding
// a new kind of object to the graph, every step is lowered to an ordinary
// managed resource of the built-in conn3x provider:
//
//	circuit "web" { step "motd" { file { ... } } }
//
// becomes resource "conn3x_file" "web__motd", repeated with for_each over
// the circuit's hosts, with an ssh block whose host is each.value, and
// depending on the step before it. Plan, apply, state, references and drift
// detection then work exactly as they do for any other resource.

const circuitFileExt = ".circuit.hcl"

// circuitModules maps a step's module block name to its resource type.
var circuitModules = map[string]string{
	"authorized_key":   "conn3x_authorized_key",
	"command":          "conn3x_command",
	"cron":             "conn3x_cron",
	"timer":            "conn3x_timer",
	"sysctl":           "conn3x_sysctl",
	"hostname":         "conn3x_hostname",
	"timezone":         "conn3x_timezone",
	"locale":           "conn3x_locale",
	"firewalld":        "conn3x_firewalld",
	"ufw":              "conn3x_ufw_rule",
	"selinux_boolean":  "conn3x_selinux_boolean",
	"selinux_fcontext": "conn3x_selinux_fcontext",
	"repository":       "conn3x_repository",
	"download":         "conn3x_download",
	"archive":          "conn3x_archive",
	"git":              "conn3x_git",
	"mount":            "conn3x_mount",
	"wait_for":         "conn3x_wait_for",
	"reboot":           "conn3x_reboot",
	"directory":        "conn3x_directory",
	"link":             "conn3x_link",
	"line":             "conn3x_line",
	"block":            "conn3x_block",
	"file":             "conn3x_file",
	"package":          "conn3x_package",
	"service":          "conn3x_service",
	"user":             "conn3x_user",
	"group":            "conn3x_group",
}

// Conn3xStepModules maps each circuit step module to its resource type.
func Conn3xStepModules() map[string]string {
	out := make(map[string]string, len(circuitModules))
	for name, rt := range circuitModules {
		out[name] = rt
	}
	return out
}

// Conn3xStepResourceTypes lists the resource types circuit steps lower to.
func Conn3xStepResourceTypes() []string {
	types := make([]string, 0, len(circuitModules))
	for _, rt := range circuitModules {
		types = append(types, rt)
	}
	return types
}

var circuitSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "hosts", Required: true},
	},
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "ssh"},
		{Type: "step", LabelNames: []string{"name"}},
		{Type: "handler", LabelNames: []string{"name"}},
	},
}

// circuitFileExtOf reports whether path is a circuit file.
func circuitFileExtOf(path string) string {
	if strings.HasSuffix(path, circuitFileExt) {
		return circuitFileExt
	}
	return ""
}

// decodeCircuitBlock lowers one circuit block to managed resources. seen
// tracks circuit names already declared in the same file.
func decodeCircuitBlock(block *hcl.Block, seen map[string]hcl.Range) ([]*Resource, hcl.Diagnostics) {
	var diags hcl.Diagnostics
	name := block.Labels[0]
	if !validCircuitName(name) {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid circuit name",
			Detail:   "A circuit name must be a valid identifier without a double underscore, which Conn3x uses to separate circuit and step names.",
			Subject:  &block.LabelRanges[0],
		})
		return nil, diags
	}
	if prev, dup := seen[name]; dup {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Duplicate circuit",
			Detail:   fmt.Sprintf("A circuit named %q was already declared at %s. Circuit names must be unique within a module.", name, prev),
			Subject:  &block.DefRange,
		})
		return nil, diags
	}
	seen[name] = block.DefRange

	content, moreDiags := block.Body.Content(circuitSchema)
	diags = append(diags, moreDiags...)
	if moreDiags.HasErrors() {
		return nil, diags
	}
	hosts := content.Attributes["hosts"].Expr

	var sshAttrs hclsyntax.Attributes
	var sshRange hcl.Range
	switch n := len(content.Blocks.OfType("ssh")); {
	case n == 0:
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Missing ssh block",
			Detail:   "A circuit needs an ssh block that says how to log in to its hosts.",
			Subject:  &block.DefRange,
		})
		return nil, diags
	case n > 1:
		second := content.Blocks.OfType("ssh")[1]
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Duplicate ssh block",
			Detail:   "A circuit has one ssh block.",
			Subject:  &second.DefRange,
		})
		return nil, diags
	default:
		ssh := content.Blocks.OfType("ssh")[0]
		sshRange = ssh.DefRange
		body, ok := ssh.Body.(*hclsyntax.Body)
		if !ok {
			diags = append(diags, nativeSyntaxRequired(ssh.DefRange))
			return nil, diags
		}
		if attr, ok := body.Attributes["host"]; ok {
			rng := attr.SrcRange
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Unexpected host in a circuit's ssh block",
				Detail:   "Each host's address comes from hosts, so the circuit's ssh block must not set host.",
				Subject:  &rng,
			})
			return nil, diags
		}
		sshAttrs = body.Attributes
	}

	var resources []*Resource
	steps := map[string]hcl.Range{}
	var previous *Resource
	notifiers := map[string][]*Resource{} // handler name => steps that notify it
	notifyRefs := map[string][]hcl.Range{}
	for _, step := range content.Blocks.OfType("step") {
		stepName := step.Labels[0]
		if !validCircuitName(stepName) {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid step name",
				Detail:   "A step name must be a valid identifier without a double underscore.",
				Subject:  &step.LabelRanges[0],
			})
			continue
		}
		if prev, dup := steps[stepName]; dup {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Duplicate step",
				Detail:   fmt.Sprintf("Circuit %q already has a step named %q, declared at %s.", name, stepName, prev),
				Subject:  &step.DefRange,
			})
			continue
		}
		steps[stepName] = step.DefRange

		stepHosts := hosts
		if previous == nil {
			// Checked on the first step only, so a bad host is reported once.
			stepHosts = &checkedHosts{hosts}
		}
		r, stepDiags := lowerStep(name, step, stepHosts, sshAttrs, sshRange, previous)
		diags = append(diags, stepDiags...)
		if r != nil {
			resources = append(resources, r)
			previous = r
			notified, notifyDiags := stepNotify(step)
			diags = append(diags, notifyDiags...)
			for _, n := range notified {
				notifiers[n.name] = append(notifiers[n.name], r)
				notifyRefs[n.name] = append(notifyRefs[n.name], n.rng)
			}
		}
	}

	diags = append(diags, warnOnConflictingEdits(content.Blocks.OfType("step"))...)

	handlers := map[string]bool{}
	for _, h := range content.Blocks.OfType("handler") {
		hName := h.Labels[0]
		if !validCircuitName(hName) {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid handler name",
				Detail:   "A handler name must be a valid identifier without a double underscore.",
				Subject:  &h.LabelRanges[0],
			})
			continue
		}
		if handlers[hName] {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Duplicate handler",
				Detail:   fmt.Sprintf("Circuit %q already has a handler named %q.", name, hName),
				Subject:  &h.DefRange,
			})
			continue
		}
		handlers[hName] = true
		if len(notifiers[hName]) == 0 {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagWarning,
				Summary:  "Unused handler",
				Detail:   fmt.Sprintf("No step in circuit %q notifies handler %q, so it never runs.", name, hName),
				Subject:  &h.DefRange,
			})
			continue
		}
		r, hDiags := lowerHandler(name, h, hosts, sshAttrs, sshRange, notifiers[hName], previous)
		diags = append(diags, hDiags...)
		if r != nil {
			resources = append(resources, r)
		}
	}
	for hName, ranges := range notifyRefs {
		if !handlers[hName] {
			for _, rng := range ranges {
				rng := rng
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  fmt.Sprintf("No handler %q", hName),
					Detail:   fmt.Sprintf("Circuit %q has no handler named %q.", name, hName),
					Subject:  &rng,
				})
			}
		}
	}
	return resources, diags
}

func lowerStep(circuit string, step *hcl.Block, hosts hcl.Expression, sshAttrs hclsyntax.Attributes, sshRange hcl.Range, previous *Resource) (*Resource, hcl.Diagnostics) {
	var diags hcl.Diagnostics
	body, ok := step.Body.(*hclsyntax.Body)
	if !ok {
		return nil, append(diags, nativeSyntaxRequired(step.DefRange))
	}
	for attrName, attr := range body.Attributes {
		if attrName != "depends_on" && attrName != "notify" && attrName != "for_each" {
			rng := attr.SrcRange
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Unsupported argument in step",
				Detail:   fmt.Sprintf("A step takes only for_each, depends_on, notify and one module block, not %q.", attrName),
				Subject:  &rng,
			})
		}
	}
	if len(body.Blocks) != 1 {
		rng := step.DefRange
		return nil, append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "A step needs exactly one module",
			Detail:   fmt.Sprintf("Each step contains exactly one module block, such as %s.", moduleList()),
			Subject:  &rng,
		})
	}
	module := body.Blocks[0]
	resourceType, ok := circuitModules[module.Type]
	moduleAttrs := module.Body.Attributes
	if module.Type == "template" {
		attrs, templateDiags := lowerTemplate(module)
		diags = append(diags, templateDiags...)
		if templateDiags.HasErrors() {
			return nil, diags
		}
		resourceType, ok, moduleAttrs = "conn3x_file", true, attrs
	}
	if !ok {
		rng := module.TypeRange
		return nil, append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Unknown module %q", module.Type),
			Detail:   fmt.Sprintf("Supported modules are %s.", moduleList()),
			Subject:  &rng,
		})
	}
	items, looping := body.Attributes["for_each"]
	diags = append(diags, loopRefs(moduleAttrs, module.Body.Blocks, looping)...)
	if diags.HasErrors() {
		return nil, diags
	}
	forEach, hostPath := hosts, []string{"value"}
	if looping {
		forEach, hostPath = &hostItemProduct{hosts: hosts, items: items.Expr}, []string{"value", "host"}
	}

	config := &hclsyntax.Body{
		Attributes: moduleAttrs,
		Blocks:     append(append(hclsyntax.Blocks{}, module.Body.Blocks...), sshBlockFor(sshAttrs, sshRange, hostPath)),
		SrcRange:   module.Body.SrcRange,
		EndRange:   module.Body.EndRange,
	}

	r := &Resource{
		Mode:      addrs.ManagedResourceMode,
		Type:      resourceType,
		Name:      circuit + "__" + step.Labels[0],
		Config:    config,
		ForEach:   forEach,
		DeclRange: step.DefRange,
		TypeRange: module.TypeRange,
		Managed:   &ManagedResource{},
	}
	if attr, ok := body.Attributes["depends_on"]; ok {
		deps, depsDiags := decodeDependsOn(attr.AsHCLAttribute())
		diags = append(diags, depsDiags...)
		r.DependsOn = append(r.DependsOn, deps...)
	}
	if previous != nil {
		r.DependsOn = append(r.DependsOn, hcl.Traversal{
			hcl.TraverseRoot{Name: previous.Type, SrcRange: step.DefRange},
			hcl.TraverseAttr{Name: previous.Name, SrcRange: step.DefRange},
		})
	}
	return r, diags
}

// sshBlockFor is a step's ssh block: the circuit's settings plus this
// host's address, each.value.
// hostOverrides are the ssh settings a host object in hosts may set for
// itself, over the circuit's ssh block.
var hostOverrides = []string{"user", "port", "private_key_file", "host_key", "jump_hosts"}

// sshBlockFor builds a step's ssh block. A host in hosts is either an
// address or an object with an address and any of hostOverrides:
//
//	host = try(each.value.address, each.value)
//	port = try(each.value.port, <the circuit's port, or null>)
//
// hostPath is where the host's entry sits under each: ["value"] for a plain
// step, ["value", "host"] for a looping one.
func sshBlockFor(sshAttrs hclsyntax.Attributes, sshRange hcl.Range, hostPath []string) *hclsyntax.Block {
	ssh := hclsyntax.Attributes{}
	for k, v := range sshAttrs {
		if len(hostPath) > 1 {
			// A looping step's each is the instance; the ssh block means the host.
			v = &hclsyntax.Attribute{Name: v.Name, Expr: eachMeansHost(v.Expr, v.SrcRange), SrcRange: v.SrcRange, NameRange: v.NameRange, EqualsRange: v.EqualsRange}
		}
		ssh[k] = v
	}
	attr := func(name string, expr hclsyntax.Expression) *hclsyntax.Attribute {
		return &hclsyntax.Attribute{Name: name, Expr: expr, SrcRange: sshRange, NameRange: sshRange}
	}
	try := func(args ...hclsyntax.Expression) hclsyntax.Expression {
		return &hclsyntax.FunctionCallExpr{Name: "try", Args: args, NameRange: sshRange, OpenParenRange: sshRange, CloseParenRange: sshRange}
	}
	ssh["host"] = attr("host", try(eachPath(sshRange, append(hostPath[:len(hostPath):len(hostPath)], "address")...), eachPath(sshRange, hostPath...)))
	for _, name := range hostOverrides {
		var fallback hclsyntax.Expression = &hclsyntax.LiteralValueExpr{Val: cty.NullVal(cty.DynamicPseudoType), SrcRange: sshRange}
		if a, ok := ssh[name]; ok {
			fallback = a.Expr
		}
		ssh[name] = attr(name, try(eachPath(sshRange, append(hostPath[:len(hostPath):len(hostPath)], name)...), fallback))
	}
	return &hclsyntax.Block{
		Type:            "ssh",
		Body:            &hclsyntax.Body{Attributes: ssh, SrcRange: sshRange, EndRange: sshRange},
		TypeRange:       sshRange,
		OpenBraceRange:  sshRange,
		CloseBraceRange: sshRange,
	}
}

// eachPath is each.<path...>.
func eachPath(rng hcl.Range, path ...string) *hclsyntax.ScopeTraversalExpr {
	t := hcl.Traversal{hcl.TraverseRoot{Name: "each", SrcRange: rng}}
	for _, p := range path {
		t = append(t, hcl.TraverseAttr{Name: p, SrcRange: rng})
	}
	return &hclsyntax.ScopeTraversalExpr{Traversal: t, SrcRange: rng}
}

func eachTraversal(attr string, rng hcl.Range) *hclsyntax.ScopeTraversalExpr {
	return &hclsyntax.ScopeTraversalExpr{
		Traversal: hcl.Traversal{hcl.TraverseRoot{Name: "each", SrcRange: rng}, hcl.TraverseAttr{Name: attr, SrcRange: rng}},
		SrcRange:  rng,
	}
}

type notifyRef struct {
	name string
	rng  hcl.Range
}

// stepNotify reads a step's notify = [handler.<name>, ...].
func stepNotify(step *hcl.Block) ([]notifyRef, hcl.Diagnostics) {
	body, ok := step.Body.(*hclsyntax.Body)
	if !ok {
		return nil, nil
	}
	attr, ok := body.Attributes["notify"]
	if !ok {
		return nil, nil
	}
	var diags hcl.Diagnostics
	exprs, listDiags := hcl.ExprList(attr.Expr)
	diags = append(diags, listDiags...)
	var refs []notifyRef
	for _, e := range exprs {
		tr, trDiags := hcl.AbsTraversalForExpr(e)
		if trDiags.HasErrors() || len(tr) != 2 || tr.RootName() != "handler" {
			rng := e.Range()
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid notify reference",
				Detail:   "notify takes a list of handler.<name> references to handlers in the same circuit.",
				Subject:  &rng,
			})
			continue
		}
		refs = append(refs, notifyRef{name: tr[1].(hcl.TraverseAttr).Name, rng: e.Range()})
	}
	return refs, diags
}

var handlerServiceSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "name", Required: true}, {Name: "action"}},
}

// lowerHandler turns a handler into a conn3x_service_action whose triggers
// are the notifying steps on the same host, so it runs only after one of
// them changed, and always after them.
func lowerHandler(circuit string, h *hcl.Block, hosts hcl.Expression, sshAttrs hclsyntax.Attributes, sshRange hcl.Range, notifiers []*Resource, last *Resource) (*Resource, hcl.Diagnostics) {
	var diags hcl.Diagnostics
	body, ok := h.Body.(*hclsyntax.Body)
	if !ok {
		return nil, append(diags, nativeSyntaxRequired(h.DefRange))
	}
	if len(body.Attributes) != 0 || len(body.Blocks) != 1 || body.Blocks[0].Type != "service" {
		rng := h.DefRange
		return nil, append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "A handler needs exactly one service block",
			Detail:   "Handlers restart or reload a service: handler \"name\" { service { name = \"nginx\" } }, with an optional action = \"reload\".",
			Subject:  &rng,
		})
	}
	svc := body.Blocks[0]
	if _, contentDiags := svc.Body.Content(handlerServiceSchema); contentDiags.HasErrors() {
		return nil, append(diags, contentDiags...)
	}

	var triggers []hclsyntax.Expression
	for _, n := range notifiers {
		if _, looping := n.ForEach.(*hostItemProduct); looping {
			step := &hclsyntax.ScopeTraversalExpr{
				Traversal: hcl.Traversal{hcl.TraverseRoot{Name: n.Type, SrcRange: h.DefRange}, hcl.TraverseAttr{Name: n.Name, SrcRange: h.DefRange}},
				SrcRange:  h.DefRange,
			}
			triggers = append(triggers, hostInstances(step, h.DefRange))
			continue
		}
		// Watch the step's revision on this host, which changes whenever
		// Conn3x changes something there.
		triggers = append(triggers, &hclsyntax.RelativeTraversalExpr{
			Source: &hclsyntax.IndexExpr{
				Collection: &hclsyntax.ScopeTraversalExpr{
					Traversal: hcl.Traversal{hcl.TraverseRoot{Name: n.Type, SrcRange: h.DefRange}, hcl.TraverseAttr{Name: n.Name, SrcRange: h.DefRange}},
					SrcRange:  h.DefRange,
				},
				Key:          eachTraversal("key", h.DefRange),
				SrcRange:     h.DefRange,
				OpenRange:    h.DefRange,
				BracketRange: h.DefRange,
			},
			Traversal: hcl.Traversal{hcl.TraverseAttr{Name: "revision", SrcRange: h.DefRange}},
			SrcRange:  h.DefRange,
		})
	}
	attrs := hclsyntax.Attributes{}
	for k, v := range svc.Body.Attributes {
		attrs[k] = v
	}
	attrs["triggers"] = &hclsyntax.Attribute{
		Name:      "triggers",
		Expr:      &hclsyntax.TupleConsExpr{Exprs: triggers, SrcRange: h.DefRange, OpenRange: h.DefRange},
		SrcRange:  h.DefRange,
		NameRange: h.DefRange,
	}
	r := &Resource{
		Mode:      addrs.ManagedResourceMode,
		Type:      "conn3x_service_action",
		Name:      circuit + "__" + h.Labels[0],
		Config:    &hclsyntax.Body{Attributes: attrs, Blocks: hclsyntax.Blocks{sshBlockFor(sshAttrs, sshRange, []string{"value"})}, SrcRange: svc.Body.SrcRange, EndRange: svc.Body.EndRange},
		ForEach:   hosts,
		DeclRange: h.DefRange,
		TypeRange: svc.TypeRange,
		Managed:   &ManagedResource{},
	}
	// Like Ansible, handlers run after every step in the circuit.
	if last != nil {
		r.DependsOn = append(r.DependsOn, hcl.Traversal{
			hcl.TraverseRoot{Name: last.Type, SrcRange: h.DefRange},
			hcl.TraverseAttr{Name: last.Name, SrcRange: h.DefRange},
		})
	}
	return r, diags
}

var templateSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "source", Required: true},
		{Name: "destination", Required: true},
		{Name: "vars"},
		{Name: "mode"},
		{Name: "owner"},
		{Name: "group"},
		{Name: "on_remove"},
		{Name: "write_only"},
	},
}

// lowerTemplate turns a template module into conn3x_file arguments. The
// template renders on the controller with templatefile(), so only the
// finished bytes travel to the host:
//
//	template { source = S, destination = D, vars = V }
//	  => path = D, content = templatefile(S, V)
//
// With write_only = true the rendered file goes to content_wo instead, so it
// stays out of state.
func lowerTemplate(module *hclsyntax.Block) (hclsyntax.Attributes, hcl.Diagnostics) {
	_, diags := module.Body.Content(templateSchema)
	if diags.HasErrors() {
		return nil, diags
	}
	in := module.Body.Attributes
	out := hclsyntax.Attributes{}
	for _, name := range []string{"mode", "owner", "group", "on_remove"} {
		if a, ok := in[name]; ok {
			out[name] = a
		}
	}
	dest := in["destination"]
	out["path"] = &hclsyntax.Attribute{Name: "path", Expr: dest.Expr, SrcRange: dest.SrcRange, NameRange: dest.NameRange, EqualsRange: dest.EqualsRange}

	src := in["source"]
	var vars hclsyntax.Expression = &hclsyntax.ObjectConsExpr{SrcRange: src.SrcRange, OpenRange: src.SrcRange}
	if v, ok := in["vars"]; ok {
		vars = v.Expr
	}
	content := "content"
	if wo, ok := in["write_only"]; ok {
		v, valDiags := wo.Expr.Value(nil)
		if valDiags.HasErrors() || !v.Type().Equals(cty.Bool) || v.IsNull() {
			return nil, hcl.Diagnostics{{
				Severity: hcl.DiagError,
				Summary:  "write_only must be true or false",
				Detail:   "write_only decides how the file is stored before anything is evaluated, so it takes a literal true or false.",
				Subject:  wo.Expr.Range().Ptr(),
			}}
		}
		if v.True() {
			content = "content_wo"
		}
	}
	out[content] = &hclsyntax.Attribute{
		Name: content,
		Expr: &hclsyntax.FunctionCallExpr{
			Name:            "templatefile",
			Args:            []hclsyntax.Expression{src.Expr, vars},
			NameRange:       src.NameRange,
			OpenParenRange:  src.SrcRange,
			CloseParenRange: src.SrcRange,
		},
		SrcRange:  src.SrcRange,
		NameRange: src.NameRange,
	}
	return out, nil
}

// warnOnConflictingEdits warns when a step writes a whole file that another
// step edits in part: each apply, one undoes the other.
func warnOnConflictingEdits(steps hcl.Blocks) hcl.Diagnostics {
	var diags hcl.Diagnostics
	whole := map[string]hcl.Range{}
	parts := map[string]hcl.Range{}
	for _, step := range steps {
		body, ok := step.Body.(*hclsyntax.Body)
		if !ok || len(body.Blocks) != 1 {
			continue
		}
		module := body.Blocks[0]
		attr := module.Body.Attributes["path"]
		if module.Type == "template" {
			attr = module.Body.Attributes["destination"]
		}
		if attr == nil {
			continue
		}
		v, valDiags := attr.Expr.Value(nil)
		if valDiags.HasErrors() || !v.Type().Equals(cty.String) || v.IsNull() {
			continue // only literal paths can be compared here
		}
		switch module.Type {
		case "file", "template":
			whole[v.AsString()] = step.DefRange
		case "line", "block":
			parts[v.AsString()] = step.DefRange
		}
	}
	for path, rng := range parts {
		if wholeRange, ok := whole[path]; ok {
			rng := rng
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagWarning,
				Summary:  "File is both edited and written whole",
				Detail:   fmt.Sprintf("%s is written in full by the step at %s and edited by this step, so every apply undoes the other. Put the edit into the file's content instead.", path, wholeRange),
				Subject:  &rng,
			})
		}
	}
	return diags
}

func validCircuitName(name string) bool {
	return hclsyntax.ValidIdentifier(name) && !strings.Contains(name, "__")
}

func moduleList() string {
	names := []string{`"template"`}
	for name := range circuitModules {
		names = append(names, fmt.Sprintf("%q", name))
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func nativeSyntaxRequired(rng hcl.Range) *hcl.Diagnostic {
	return &hcl.Diagnostic{
		Severity: hcl.DiagError,
		Summary:  "Circuits need native syntax",
		Detail:   "Circuits can be written in .circuit.hcl or .tf files, but not in JSON.",
		Subject:  &rng,
	}
}
