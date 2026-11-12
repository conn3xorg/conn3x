// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// A rescue runs on a host only when a step or handler it watches failed
// there, like a step in Ansible's rescue:
//
//	rescue "restore" {
//	  watches = [step.config, handler.restart]
//	  command { command = "cp /var/backups/app.conf /etc/app/app.conf" }
//	}
//
// It lowers like a step, but has no instances in a plan: conn3x apply runs
// the rescues in a plan of their own after an apply in which a watched step
// failed, on the hosts where it failed, and then drops them from state (see
// cmd/conn3x/conn3x_rescue.go and docs/rescue-design.md).

// Conn3xRescueHosts is set in the plan a rescue phase makes: each rescue's
// resource name to the hosts it runs on. While it's nil, a rescue has no
// instances.
var Conn3xRescueHosts map[string][]string

// rescueFilter is a rescue's for_each: no instances, or in a rescue phase
// the instances on the hosts Conn3xRescueHosts gives it.
type rescueFilter struct {
	instances hcl.Expression
	name      string // the rescue's resource name, circuit__rescue
	looping   bool
}

var _ hcl.Expression = (*rescueFilter)(nil)

func (f *rescueFilter) Value(ctx *hcl.EvalContext) (cty.Value, hcl.Diagnostics) {
	// Evaluated outside the phase too, so a mistake in hosts or when shows
	// in every plan rather than only after a failure.
	all, diags := f.instances.Value(ctx)
	if diags.HasErrors() {
		return cty.DynamicVal, diags
	}
	all, marks := all.Unmark()
	if !all.IsKnown() || all.IsNull() {
		return cty.DynamicVal.WithMarks(marks), diags
	}
	hosts := Conn3xRescueHosts[f.name]
	kept := map[string]cty.Value{}
	for it := all.ElementIterator(); it.Next(); {
		k, v := it.Element()
		host := k.AsString()
		if f.looping {
			host = v.GetAttr("host_key").AsString()
		}
		if slices.Contains(hosts, host) {
			kept[k.AsString()] = v
		}
	}
	if len(kept) == 0 {
		return cty.EmptyObjectVal.WithMarks(marks), diags
	}
	return cty.ObjectVal(kept).WithMarks(marks), diags
}

func (f *rescueFilter) Variables() []hcl.Traversal { return f.instances.Variables() }
func (f *rescueFilter) Range() hcl.Range           { return f.instances.Range() }
func (f *rescueFilter) StartRange() hcl.Range      { return f.instances.StartRange() }

// Conn3xRescueResource reports whether r is a circuit's rescue.
func Conn3xRescueResource(r *Resource) bool {
	_, ok := r.ForEach.(*rescueFilter)
	return ok
}

// Conn3xRescue is one rescue, as conn3x apply needs it.
type Conn3xRescue struct {
	Circuit, Name string
	// Watches are the step and handler names it watches, in the order
	// written. A step and a handler can't share a name.
	Watches []string
}

// Resource is the rescue's resource name.
func (r Conn3xRescue) Resource() string { return r.Circuit + "__" + r.Name }

// rescueRefuses are the step arguments a rescue doesn't take, and why.
var rescueRefuses = map[string]string{
	"depends_on": "A rescue runs after the steps it watches, in a plan of its own, so it can't wait for anything else.",
	"run_once":   "A rescue runs on each host where a watched step failed.",
	"import":     "A rescue is dropped from state once it has run, so there's nothing to import into.",
	"notify":     "A rescue can't notify a handler yet. Put the restart in the rescue itself.",
}

// rescueWatches reads a rescue's watches = [step.<name>, handler.<name>, ...].
func rescueWatches(rescue *hcl.Block) ([]string, hcl.Diagnostics) {
	body, ok := rescue.Body.(*hclsyntax.Body)
	if !ok {
		return nil, hcl.Diagnostics{nativeSyntaxRequired(rescue.DefRange)}
	}
	attr, ok := body.Attributes["watches"]
	if !ok {
		return nil, hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Missing watches in rescue",
			Detail:   "A rescue runs on a host where a step or handler it watches failed: watches = [step.config, handler.restart].",
			Subject:  rescue.DefRange.Ptr(),
		}}
	}
	exprs, diags := hcl.ExprList(attr.Expr)
	var names []string
	for _, e := range exprs {
		t, tDiags := hcl.AbsTraversalForExpr(e)
		if tDiags.HasErrors() || len(t) != 2 || (t.RootName() != "step" && t.RootName() != "handler") {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid watches in rescue",
				Detail:   "watches takes a list of step.<name> and handler.<name> references to steps and handlers in the same circuit.",
				Subject:  e.Range().Ptr(),
			})
			continue
		}
		names = append(names, t[1].(hcl.TraverseAttr).Name)
	}
	if len(exprs) == 0 && !diags.HasErrors() {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Empty watches in rescue",
			Detail:   "A rescue that watches nothing never runs. Name the steps and handlers it rescues.",
			Subject:  attr.SrcRange.Ptr(),
		})
	}
	return names, diags
}

// lowerRescues lowers a circuit's rescues. steps and handlers are the
// circuit's, by name, to check watches against; a rescue's name must not
// be one of theirs, since they share resource names.
func lowerRescues(circuit string, rescues hcl.Blocks, steps, handlers map[string]bool, hosts hcl.Expression, sshAttrs hclsyntax.Attributes, sshRange hcl.Range, perHost bool) ([]*Resource, hcl.Diagnostics) {
	var diags hcl.Diagnostics
	var out, chain []*Resource
	seen := map[string]bool{}
	for _, rescue := range rescues {
		name := rescue.Labels[0]
		switch {
		case !validCircuitName(name):
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid rescue name",
				Detail:   "A rescue name must be a valid identifier without a double underscore.",
				Subject:  &rescue.LabelRanges[0],
			})
			continue
		case steps[name] || handlers[name] || seen[name]:
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Duplicate rescue",
				Detail:   fmt.Sprintf("Circuit %q already has a step, handler or rescue named %q. They share names.", circuit, name),
				Subject:  &rescue.DefRange,
			})
			continue
		}
		seen[name] = true
		body, ok := rescue.Body.(*hclsyntax.Body)
		if !ok {
			diags = append(diags, nativeSyntaxRequired(rescue.DefRange))
			continue
		}
		watches, wDiags := rescueWatches(rescue)
		diags = append(diags, wDiags...)
		for i, w := range watches {
			if !steps[w] && !handlers[w] {
				e, _ := hcl.ExprList(body.Attributes["watches"].Expr)
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  fmt.Sprintf("No step or handler %q", w),
					Detail:   fmt.Sprintf("Circuit %q has no step or handler named %q for rescue %q to watch.", circuit, w, name),
					Subject:  e[i].Range().Ptr(),
				})
			}
		}
		attrs := hclsyntax.Attributes{}
		for k, a := range body.Attributes {
			if why, refused := rescueRefuses[k]; refused {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  fmt.Sprintf("Unsupported argument %q in rescue", k),
					Detail:   why,
					Subject:  a.SrcRange.Ptr(),
				})
			} else if k != "watches" {
				attrs[k] = a
			}
		}
		if diags.HasErrors() {
			continue
		}
		stripped := *body
		stripped.Attributes = attrs
		step := *rescue
		step.Body = &stripped
		r, _, stepDiags := lowerStep(circuit, &step, hosts, sshAttrs, sshRange, chain, perHost)
		diags = append(diags, stepDiags...)
		if r == nil {
			continue
		}
		r.ForEach = &rescueFilter{instances: r.ForEach, name: r.Name, looping: stepLoops(r.ForEach)}
		out = append(out, r)
		chain = chainAfter(chain, r, perHost)
	}
	return out, diags
}

// Conn3xRescues reads the rescues of the circuits in the root module in
// dir. It reads only what conn3x apply needs; the full checks run when the
// configuration loads.
func Conn3xRescues(dir string) ([]Conn3xRescue, hcl.Diagnostics) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, hcl.Diagnostics{{Severity: hcl.DiagError, Summary: "Can't read the configuration directory", Detail: err.Error()}}
	}
	var out []Conn3xRescue
	var diags hcl.Diagnostics
	p := hclparse.NewParser()
	for _, e := range entries {
		if e.IsDir() || circuitFileExtOf(e.Name()) == "" {
			continue
		}
		f, fDiags := p.ParseHCLFile(filepath.Join(dir, e.Name()))
		diags = append(diags, fDiags...)
		if f == nil {
			continue
		}
		top, _, _ := f.Body.PartialContent(&hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "circuit", LabelNames: []string{"name"}}}})
		for _, block := range top.Blocks {
			content, _, _ := block.Body.PartialContent(circuitSchema)
			for _, rescue := range content.Blocks.OfType("rescue") {
				watches, wDiags := rescueWatches(rescue)
				diags = append(diags, wDiags...)
				out = append(out, Conn3xRescue{Circuit: block.Labels[0], Name: rescue.Labels[0], Watches: watches})
			}
		}
	}
	return out, diags
}
