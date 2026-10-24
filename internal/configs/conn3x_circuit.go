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
	"file": "conn3x_file",
}

var circuitSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "hosts", Required: true},
	},
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "ssh"},
		{Type: "step", LabelNames: []string{"name"}},
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
		if attrName != "depends_on" {
			rng := attr.SrcRange
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Unsupported argument in step",
				Detail:   fmt.Sprintf("A step takes only depends_on and one module block, not %q.", attrName),
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

	// The step's ssh block: the circuit's settings plus this host's address.
	ssh := hclsyntax.Attributes{}
	for k, v := range sshAttrs {
		ssh[k] = v
	}
	ssh["host"] = &hclsyntax.Attribute{
		Name: "host",
		Expr: &hclsyntax.ScopeTraversalExpr{
			Traversal: hcl.Traversal{hcl.TraverseRoot{Name: "each", SrcRange: sshRange}, hcl.TraverseAttr{Name: "value", SrcRange: sshRange}},
			SrcRange:  sshRange,
		},
		SrcRange:  sshRange,
		NameRange: sshRange,
	}
	config := &hclsyntax.Body{
		Attributes: module.Body.Attributes,
		Blocks: append(append(hclsyntax.Blocks{}, module.Body.Blocks...), &hclsyntax.Block{
			Type:            "ssh",
			Body:            &hclsyntax.Body{Attributes: ssh, SrcRange: sshRange, EndRange: sshRange},
			TypeRange:       sshRange,
			OpenBraceRange:  sshRange,
			CloseBraceRange: sshRange,
		}),
		SrcRange: module.Body.SrcRange,
		EndRange: module.Body.EndRange,
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

func validCircuitName(name string) bool {
	return hclsyntax.ValidIdentifier(name) && !strings.Contains(name, "__")
}

func moduleList() string {
	names := make([]string, 0, len(circuitModules))
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
