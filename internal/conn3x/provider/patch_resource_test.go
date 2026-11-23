// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/modules/patch"
	"github.com/opentofu/opentofu/internal/providers"
)

func TestPatchValidate(t *testing.T) {
	c, d := cty.StringVal("--- a\n+++ b\n"), cty.StringVal("/etc/app.conf")
	for name, attrs := range map[string]map[string]cty.Value{
		"neither":     {"dest": d},
		"both dests":  {"content": c, "dest": d, "basedir": cty.StringVal("/opt")},
		"relative":    {"content": c, "dest": cty.StringVal("app.conf")},
		"half strip":  {"content": c, "dest": d, "strip": cty.NumberFloatVal(1.5)},
		"state":       {"content": c, "dest": d, "state": cty.StringVal("reverted")},
		"on_remove":   {"content": c, "dest": d, "on_remove": cty.StringVal("purge")},
		"negative -p": {"content": c, "dest": d, "strip": cty.NumberIntVal(-1)},
	} {
		if diags := validatePatch(objFor(patchSchema(), attrs)); !diags.HasErrors() {
			t.Errorf("%s: no error", name)
		}
	}
	ok := map[string]cty.Value{"src": cty.StringVal("/tmp/fix.patch"), "basedir": cty.StringVal("/opt/app"), "strip": cty.NumberIntVal(1)}
	if diags := validatePatch(objFor(patchSchema(), ok)); diags.HasErrors() {
		t.Error(diags.Err())
	}
}

// A patch found reverted by hand plans a change, with status unknown so
// apply can fill it in; one that's in plans nothing.
func TestPatchPlan(t *testing.T) {
	cfg := objFor(patchSchema(), map[string]cty.Value{"content": cty.StringVal("x"), "dest": cty.StringVal("/etc/app.conf")})
	vals := cfg.AsValueMap()
	vals["id"], vals["on_remove"] = cty.StringVal("x"), cty.StringVal("forget")
	out := patchState(cty.ObjectVal(vals), patch.NotApplied)
	if out.GetAttr("in_sync").True() || out.GetAttr("status").AsString() != "not_applied" {
		t.Fatalf("state %#v", out)
	}
	plan := planPatch(providers.PlanResourceChangeRequest{PriorState: out, ProposedNewState: out})
	if p := plan.PlannedState; p.GetAttr("in_sync").IsKnown() || p.GetAttr("status").IsKnown() {
		t.Errorf("not applied: planned %#v", p)
	}
	in := patchState(cty.ObjectVal(vals), patch.Applied)
	plan = planPatch(providers.PlanResourceChangeRequest{PriorState: in, ProposedNewState: in})
	if p := plan.PlannedState; !p.GetAttr("in_sync").RawEquals(cty.True) || p.GetAttr("status").AsString() != "applied" {
		t.Errorf("applied: planned %#v", plan.PlannedState)
	}
	vals["state"] = cty.StringVal("absent")
	if patchState(cty.ObjectVal(vals), patch.NotApplied).GetAttr("in_sync").False() {
		t.Error("absent and not applied should be in sync")
	}
}
