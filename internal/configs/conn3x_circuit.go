// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

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
	"command": "conn3x_command",
	"file":    "conn3x_file",
	"package": "conn3x_package",
	"service": "conn3x_service",
	"user":    "conn3x_user",
	"group":   "conn3x_group",
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

		r, stepDiags := lowerStep(name, step, hosts, sshAttrs, sshRange, previous)
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
		if attrName != "depends_on" && attrName != "notify" {
			rng := attr.SrcRange
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Unsupported argument in step",
				Detail:   fmt.Sprintf("A step takes only depends_on, notify and one module block, not %q.", attrName),
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
	if diags.HasErrors() {
		return nil, diags
	}

	config := &hclsyntax.Body{
		Attributes: moduleAttrs,
		Blocks:     append(append(hclsyntax.Blocks{}, module.Body.Blocks...), sshBlockFor(sshAttrs, sshRange)),
		SrcRange:   module.Body.SrcRange,
		EndRange:   module.Body.EndRange,
	}

	r := &Resource{
		Mode:      addrs.ManagedResourceMode,
		Type:      resourceType,
		Name:      circuit + "__" + step.Labels[0],
		Config:    config,
		ForEach:   hosts,
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
func sshBlockFor(sshAttrs hclsyntax.Attributes, sshRange hcl.Range) *hclsyntax.Block {
	ssh := hclsyntax.Attributes{}
	for k, v := range sshAttrs {
		ssh[k] = v
	}
	ssh["host"] = &hclsyntax.Attribute{
		Name:      "host",
		Expr:      eachTraversal("value", sshRange),
		SrcRange:  sshRange,
		NameRange: sshRange,
	}
	return &hclsyntax.Block{
		Type:            "ssh",
		Body:            &hclsyntax.Body{Attributes: ssh, SrcRange: sshRange, EndRange: sshRange},
		TypeRange:       sshRange,
		OpenBraceRange:  sshRange,
		CloseBraceRange: sshRange,
	}
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
		triggers = append(triggers, &hclsyntax.IndexExpr{
			Collection: &hclsyntax.ScopeTraversalExpr{
				Traversal: hcl.Traversal{hcl.TraverseRoot{Name: n.Type, SrcRange: h.DefRange}, hcl.TraverseAttr{Name: n.Name, SrcRange: h.DefRange}},
				SrcRange:  h.DefRange,
			},
			Key:          eachTraversal("key", h.DefRange),
			SrcRange:     h.DefRange,
			OpenRange:    h.DefRange,
			BracketRange: h.DefRange,
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
		Config:    &hclsyntax.Body{Attributes: attrs, Blocks: hclsyntax.Blocks{sshBlockFor(sshAttrs, sshRange)}, SrcRange: svc.Body.SrcRange, EndRange: svc.Body.EndRange},
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
	},
}

// lowerTemplate turns a template module into conn3x_file arguments. The
// template renders on the controller with templatefile(), so only the
// finished bytes travel to the host:
//
//	template { source = S, destination = D, vars = V }
//	  => path = D, content = templatefile(S, V)
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
	out["content"] = &hclsyntax.Attribute{
		Name: "content",
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
