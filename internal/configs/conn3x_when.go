// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

// A step's when picks the hosts it runs on, like Ansible's when:
//
//	step "apt_cache" {
//	  when = local.os_family[each.key] == "debian"
//	  ...
//	}
//
// It filters the step's for_each, so a host where it's false has no
// instance of the step. That decides which instances exist, so it has to be
// known when planning, and a host that goes from true to false loses its
// instance: a removal, with the step's on_remove.

// whenFilter is a step's for_each with its when applied: the instances
// (hosts, or host/item pairs) for which when is true. In a looping step,
// when's each and item have been rewritten onto the instance object, as
// the module's arguments are, so each instance evaluates it the same way.
type whenFilter struct {
	instances hcl.Expression
	cond      hcl.Expression
}

var _ hcl.Expression = (*whenFilter)(nil)

func (w *whenFilter) Value(ctx *hcl.EvalContext) (cty.Value, hcl.Diagnostics) {
	all, diags := w.instances.Value(ctx)
	if diags.HasErrors() {
		return cty.DynamicVal, diags
	}
	all, hostMarks := all.Unmark()
	marks := []cty.ValueMarks{hostMarks}
	if !all.IsKnown() || all.IsNull() {
		return cty.DynamicVal.WithMarks(marks...), diags
	}
	rng := w.cond.Range()
	bad := func(summary, detail string) (cty.Value, hcl.Diagnostics) {
		return cty.DynamicVal, append(diags, &hcl.Diagnostic{Severity: hcl.DiagError, Summary: summary, Detail: detail, Subject: &rng})
	}
	kept := map[string]cty.Value{}
	for it := all.ElementIterator(); it.Next(); {
		k, v := it.Element()
		child := ctx.NewChild()
		child.Variables = map[string]cty.Value{"each": cty.ObjectVal(map[string]cty.Value{"key": k, "value": v})}
		got, condDiags := w.cond.Value(child)
		diags = append(diags, condDiags...)
		if condDiags.HasErrors() {
			return cty.DynamicVal, diags
		}
		got, condMarks := got.Unmark()
		marks = append(marks, condMarks)
		if !got.IsKnown() {
			return bad("when isn't known yet",
				fmt.Sprintf("when decides whether the step runs on %s, so it has to be known when planning, but on %s it depends on something only the apply will know. "+
					"A host that doesn't exist yet has no facts: give its entry in hosts the value when needs, such as os = \"ubuntu\", and read that first, as in try(each.value.os, ...).", k.AsString(), k.AsString()))
		}
		b, err := convert.Convert(got, cty.Bool)
		if err != nil || b.IsNull() {
			return bad("Invalid when in step", fmt.Sprintf("when must be true or false; on %s it is %s.", k.AsString(), describe(got)))
		}
		if b.True() {
			kept[k.AsString()] = v
		}
	}
	if len(kept) == 0 {
		return cty.EmptyObjectVal.WithMarks(marks...), diags
	}
	return cty.ObjectVal(kept).WithMarks(marks...), diags
}

func describe(v cty.Value) string {
	if v.IsNull() {
		return "null"
	}
	return v.Type().FriendlyName()
}

// Variables leaves out each and item: they're set per instance here, and
// OpenTofu would refuse them in a for_each.
func (w *whenFilter) Variables() []hcl.Traversal {
	out := append([]hcl.Traversal{}, w.instances.Variables()...)
	for _, t := range w.cond.Variables() {
		if r := t.RootName(); r != "each" && r != "item" {
			out = append(out, t)
		}
	}
	return out
}

func (w *whenFilter) Range() hcl.Range      { return w.cond.Range() }
func (w *whenFilter) StartRange() hcl.Range { return w.cond.StartRange() }

// stepLoops reports whether a step's instances are host/item pairs.
func stepLoops(forEach hcl.Expression) bool {
	switch e := forEach.(type) {
	case *hostItemProduct:
		return true
	case *whenFilter:
		return stepLoops(e.instances)
	case *onceFilter:
		return stepLoops(e.instances)
	}
	return false
}

// stepFiltered reports whether a step may have no instance on some host.
func stepFiltered(forEach hcl.Expression) bool {
	switch forEach.(type) {
	case *whenFilter, *onceFilter:
		return true
	}
	return false
}

// unfiltered is a step's instances before its when.
func unfiltered(forEach hcl.Expression) hcl.Expression {
	switch e := forEach.(type) {
	case *whenFilter:
		return e.instances
	case *onceFilter:
		return e.instances
	}
	return forEach
}
