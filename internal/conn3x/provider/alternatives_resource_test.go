// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// A name is one object per host; changing what it points to is an update.
func TestAlternativesPlan(t *testing.T) {
	r := resourceTypes["conn3x_alternatives"]
	cfg := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("editor"), "path": cty.StringVal("/bin/nano")})
	created := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
	if got := created.GetAttr("id"); !got.RawEquals(cty.StringVal("203.0.113.10:alternatives:editor")) {
		t.Errorf("id = %#v", got)
	}
	prior := withSync(created, true)
	next := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("editor"), "path": cty.StringVal("/usr/bin/vim.basic"), "priority": cty.NumberIntVal(60)})
	resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: next, Config: next})
	if len(resp.RequiresReplace) != 0 || resp.PlannedState.GetAttr("in_sync").IsKnown() {
		t.Errorf("changing path must update in place: %v", resp.RequiresReplace)
	}
	if a := alternativeFrom(resp.PlannedState); a.Priority != "60" || a.Link != "" {
		t.Errorf("alternative = %+v", a)
	}
	renamed := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("vi"), "path": cty.StringVal("/bin/nano")})
	if resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: renamed, Config: renamed}); len(resp.RequiresReplace) != 1 {
		t.Errorf("changing name must replace: %v", resp.RequiresReplace)
	}
}

func TestAlternativesValidate(t *testing.T) {
	r := resourceTypes["conn3x_alternatives"]
	for _, cfg := range []map[string]cty.Value{
		{"name": cty.StringVal("ed itor"), "path": cty.StringVal("/bin/nano")},
		{"name": cty.StringVal("editor"), "path": cty.StringVal("nano")},
		{"name": cty.StringVal("editor"), "path": cty.StringVal("/bin/nano"), "link": cty.StringVal("editor")},
		{"name": cty.StringVal("editor"), "path": cty.StringVal("/bin/nano"), "priority": cty.NumberFloatVal(1.5)},
	} {
		if diags := r.validate(objFor(r.schema(), cfg)); !diags.HasErrors() {
			t.Errorf("accepted %v", cfg)
		}
	}
	if diags := r.validate(objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("editor"), "path": cty.StringVal("/bin/nano"), "priority": cty.NumberIntVal(-100)})); diags.HasErrors() {
		t.Error(diags.Err())
	}
}
