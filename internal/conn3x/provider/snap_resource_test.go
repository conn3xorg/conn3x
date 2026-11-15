// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// A snap is one object per host; changing its channel, confinement or state
// is an update, and a different name is another snap.
func TestSnapPlan(t *testing.T) {
	r := resourceTypes["conn3x_snap"]
	cfg := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("hello-world")})
	created := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
	if got := created.GetAttr("id"); !got.RawEquals(cty.StringVal("203.0.113.10:snap:hello-world")) {
		t.Errorf("id = %#v", got)
	}
	prior := withSync(created, true)
	if resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: cfg, Config: cfg}); !resp.PlannedState.GetAttr("in_sync").RawEquals(cty.True) {
		t.Error("an unchanged, in-sync snap must plan no change")
	}
	for _, next := range []map[string]cty.Value{
		{"name": cty.StringVal("hello-world"), "channel": cty.StringVal("edge")},
		{"name": cty.StringVal("hello-world"), "classic": cty.True},
		{"name": cty.StringVal("hello-world"), "state": cty.StringVal("absent")},
	} {
		cfg := objFor(r.schema(), next)
		resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: cfg, Config: cfg})
		if len(resp.RequiresReplace) != 0 || resp.PlannedState.GetAttr("in_sync").IsKnown() {
			t.Errorf("%v must update in place: %v", next, resp.RequiresReplace)
		}
	}
	renamed := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("lxd")})
	if resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: renamed, Config: renamed}); len(resp.RequiresReplace) != 1 {
		t.Errorf("changing name must replace: %v", resp.RequiresReplace)
	}
}

func TestSnapValidate(t *testing.T) {
	r := resourceTypes["conn3x_snap"]
	for _, cfg := range []map[string]cty.Value{
		{"name": cty.StringVal("Hello")},
		{"name": cty.StringVal("hello-world"), "channel": cty.StringVal("-edge")},
		{"name": cty.StringVal("hello-world"), "state": cty.StringVal("latest")},
		{"name": cty.StringVal("hello-world"), "on_remove": cty.StringVal("purge")},
	} {
		if diags := r.validate(objFor(r.schema(), cfg)); !diags.HasErrors() {
			t.Errorf("accepted %v", cfg)
		}
	}
	if diags := r.validate(objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("microk8s"), "channel": cty.StringVal("1.28/stable"), "classic": cty.True})); diags.HasErrors() {
		t.Error(diags.Err())
	}
}
