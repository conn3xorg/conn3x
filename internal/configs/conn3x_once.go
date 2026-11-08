// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"fmt"
	"sort"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// A step with run_once runs on one host, like Ansible's run_once:
//
//	step "migrate" {
//	  run_once = true
//	  on       = "db1"   # optional; the first host key in sort order otherwise
//	  ...
//	}
//
// It filters the step's for_each to that host's instances. Even under
// per_host it's a sync point, as in Ansible: it waits for the steps before
// it on every host, and the steps after it wait for it on every host.

// onceFilter is a run_once step's for_each: the instances on one host.
type onceFilter struct {
	instances hcl.Expression
	on        hcl.Expression // nil: the first host key
	looping   bool
}

var _ hcl.Expression = (*onceFilter)(nil)

func (o *onceFilter) Value(ctx *hcl.EvalContext) (cty.Value, hcl.Diagnostics) {
	all, diags := o.instances.Value(ctx)
	if diags.HasErrors() {
		return cty.DynamicVal, diags
	}
	all, marks := all.Unmark()
	if !all.IsKnown() || all.IsNull() {
		return cty.DynamicVal.WithMarks(marks), diags
	}
	hostOf := func(k, v cty.Value) string {
		if o.looping {
			return v.GetAttr("host_key").AsString()
		}
		return k.AsString()
	}
	hosts := map[string]bool{}
	for it := all.ElementIterator(); it.Next(); {
		k, v := it.Element()
		hosts[hostOf(k, v)] = true
	}
	var target string
	if o.on == nil {
		names := make([]string, 0, len(hosts))
		for h := range hosts {
			names = append(names, h)
		}
		sort.Strings(names)
		if len(names) > 0 {
			target = names[0]
		}
	} else {
		rng := o.on.Range()
		v, onDiags := o.on.Value(ctx)
		diags = append(diags, onDiags...)
		if onDiags.HasErrors() {
			return cty.DynamicVal, diags
		}
		v, _ = v.Unmark()
		if !v.IsKnown() {
			return cty.DynamicVal, append(diags, &hcl.Diagnostic{Severity: hcl.DiagError, Summary: "on isn't known yet",
				Detail: "on names the host a run_once step runs on, so it has to be known when planning.", Subject: &rng})
		}
		if v.IsNull() || v.Type() != cty.String {
			return cty.DynamicVal, append(diags, &hcl.Diagnostic{Severity: hcl.DiagError, Summary: "Invalid on in step",
				Detail: "on is the name of one of the circuit's hosts, such as \"db1\".", Subject: &rng})
		}
		target = v.AsString()
		if !hosts[target] {
			return cty.DynamicVal, append(diags, &hcl.Diagnostic{Severity: hcl.DiagError, Summary: "Invalid on in step",
				Detail: fmt.Sprintf("on names %q, which isn't one of the circuit's hosts.", target), Subject: &rng})
		}
	}
	kept := map[string]cty.Value{}
	for it := all.ElementIterator(); it.Next(); {
		k, v := it.Element()
		if hostOf(k, v) == target {
			kept[k.AsString()] = v
		}
	}
	if len(kept) == 0 {
		return cty.EmptyObjectVal.WithMarks(marks), diags
	}
	return cty.ObjectVal(kept).WithMarks(marks), diags
}

func (o *onceFilter) Variables() []hcl.Traversal {
	out := append([]hcl.Traversal{}, o.instances.Variables()...)
	if o.on != nil {
		out = append(out, o.on.Variables()...)
	}
	return out
}

func (o *onceFilter) Range() hcl.Range {
	if o.on != nil {
		return o.on.Range()
	}
	return o.instances.Range()
}

func (o *onceFilter) StartRange() hcl.Range {
	if o.on != nil {
		return o.on.StartRange()
	}
	return o.instances.StartRange()
}

// stepOnce reports whether a step runs on one host only.
func stepOnce(forEach hcl.Expression) bool {
	_, ok := forEach.(*onceFilter)
	return ok
}
