// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func TestRebootPlan(t *testing.T) {
	r := resourceTypes["conn3x_reboot"]
	triggers := func(v string) cty.Value { return cty.MapVal(map[string]cty.Value{"kernel": cty.StringVal(v)}) }
	cfg := objFor(r.schema(), map[string]cty.Value{"triggers": triggers("6.12")})
	created := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
	if created.GetAttr("boot_id").IsKnown() || !created.GetAttr("id").RawEquals(cty.StringVal("203.0.113.10:reboot")) {
		t.Fatalf("planned = %#v", created)
	}
	vals := created.AsValueMap()
	vals["boot_id"] = cty.StringVal("b1")
	prior := cty.ObjectVal(vals)

	same := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: prior, Config: prior})
	if len(same.RequiresReplace) != 0 || !same.PlannedState.RawEquals(prior) {
		t.Fatalf("unchanged triggers must not reboot: %v", same.RequiresReplace)
	}
	vals["triggers"] = triggers("6.13")
	next := cty.ObjectVal(vals)
	changed := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: next, Config: next})
	if len(changed.RequiresReplace) != 1 || changed.PlannedState.GetAttr("boot_id").IsKnown() {
		t.Fatalf("changed triggers must reboot: %v", changed.RequiresReplace)
	}
}

func TestWaitForPlanAndValidate(t *testing.T) {
	r := resourceTypes["conn3x_wait_for"]
	cfg := objFor(r.schema(), map[string]cty.Value{"port": cty.NumberIntVal(8080)})
	planned := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
	if got := planned.GetAttr("id"); !got.RawEquals(cty.StringVal("203.0.113.10:wait_for::8080")) {
		t.Fatalf("id = %#v", got)
	}
	for _, bad := range []map[string]cty.Value{
		{"port": cty.NumberIntVal(8080), "path": cty.StringVal("/run/x")},
		{"path": cty.StringVal("/run/x"), "timeout": cty.StringVal("soon")},
	} {
		if !r.validate(objFor(r.schema(), bad)).HasErrors() {
			t.Errorf("accepted %v", bad)
		}
	}
	if !resourceTypes["conn3x_reboot"].validate(objFor(resourceTypes["conn3x_reboot"].schema(), map[string]cty.Value{"timeout": cty.StringVal("-1m")})).HasErrors() {
		t.Error("accepted a negative reboot timeout")
	}
}
