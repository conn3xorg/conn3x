// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func serviceObj(attrs map[string]cty.Value) cty.Value {
	ty := serviceSchema().Block.ImpliedType()
	vals := map[string]cty.Value{}
	for name, at := range ty.AttributeTypes() {
		vals[name] = cty.NullVal(at)
	}
	sshVals := map[string]cty.Value{}
	for name, at := range ty.AttributeType("ssh").AttributeTypes() {
		sshVals[name] = cty.NullVal(at)
	}
	sshVals["host"], sshVals["user"] = cty.StringVal("203.0.113.10"), cty.StringVal("root")
	vals["ssh"] = cty.ObjectVal(sshVals)
	for k, v := range attrs {
		vals[k] = v
	}
	return cty.ObjectVal(vals)
}

func planSvc(prior, cfg cty.Value) cty.Value {
	proposed := cfg
	if !prior.IsNull() {
		vals := cfg.AsValueMap()
		for _, n := range []string{"id", "on_remove", "running", "is_enabled"} {
			if vals[n].IsNull() {
				vals[n] = prior.GetAttr(n)
			}
		}
		proposed = cty.ObjectVal(vals)
	}
	return planService(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: proposed, Config: cfg}).PlannedState
}

func TestServicePlanNoChangeWhenRunning(t *testing.T) {
	prior := serviceObj(map[string]cty.Value{
		"id": cty.StringVal("h:service:web.service"), "name": cty.StringVal("web"), "state": cty.StringVal("started"),
		"enabled": cty.True, "on_remove": cty.StringVal("forget"), "running": cty.True, "is_enabled": cty.True,
	})
	cfg := serviceObj(map[string]cty.Value{"name": cty.StringVal("web"), "state": cty.StringVal("started"), "enabled": cty.True})
	if got := planSvc(prior, cfg).GetAttr("running"); !got.RawEquals(cty.True) {
		t.Fatalf("running = %#v, want unchanged", got)
	}
}

func TestServicePlanStartsStoppedUnit(t *testing.T) {
	prior := serviceObj(map[string]cty.Value{
		"id": cty.StringVal("h:service:web.service"), "name": cty.StringVal("web"), "state": cty.StringVal("started"),
		"on_remove": cty.StringVal("forget"), "running": cty.False, "is_enabled": cty.False,
	})
	cfg := serviceObj(map[string]cty.Value{"name": cty.StringVal("web"), "state": cty.StringVal("started")})
	if planSvc(prior, cfg).GetAttr("running").IsKnown() {
		t.Fatal("a stopped unit was not planned to start")
	}
}

func TestServicePlanMissingUnitPlansChange(t *testing.T) {
	prior := serviceObj(map[string]cty.Value{
		"id": cty.StringVal("h:service:web.service"), "name": cty.StringVal("web"), "state": cty.StringVal("started"),
		"on_remove": cty.StringVal("forget"),
	})
	cfg := serviceObj(map[string]cty.Value{"name": cty.StringVal("web"), "state": cty.StringVal("started")})
	if planSvc(prior, cfg).GetAttr("running").IsKnown() {
		t.Fatal("a missing unit was not planned")
	}
}

func TestServiceValidate(t *testing.T) {
	if !validateService(serviceObj(map[string]cty.Value{"name": cty.StringVal("web"), "state": cty.StringVal("running")})).HasErrors() {
		t.Error("bad state accepted")
	}
	if !validateService(serviceObj(map[string]cty.Value{"name": cty.StringVal("web; reboot")})).HasErrors() {
		t.Error("bad name accepted")
	}
}
