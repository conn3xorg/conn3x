// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/modules/supervisor"
	"github.com/opentofu/opentofu/internal/providers"
)

func TestSupervisorValidate(t *testing.T) {
	for name, attrs := range map[string]map[string]cty.Value{
		"all":       {"name": cty.StringVal("all"), "state": cty.StringVal("started")},
		"restarted": {"name": cty.StringVal("app"), "state": cty.StringVal("restarted")},
		"on_remove": {"name": cty.StringVal("app"), "state": cty.StringVal("started"), "on_remove": cty.StringVal("purge")},
	} {
		if diags := validateSupervisor(objFor(supervisorSchema(), attrs)); !diags.HasErrors() {
			t.Errorf("%s: no error", name)
		}
	}
	ok := map[string]cty.Value{"name": cty.StringVal("web:"), "state": cty.StringVal("stopped")}
	if diags := validateSupervisor(objFor(supervisorSchema(), ok)); diags.HasErrors() {
		t.Error(diags.Err())
	}
}

// A program found stopped plans a change, with its processes unknown so
// apply can fill them in; one in its state plans nothing.
func TestSupervisorPlan(t *testing.T) {
	cfg := objFor(supervisorSchema(), map[string]cty.Value{"name": cty.StringVal("app"), "state": cty.StringVal("started")})
	vals := cfg.AsValueMap()
	vals["id"], vals["on_remove"] = cty.StringVal("x"), cty.StringVal("forget")
	prior := supervisorState(cty.ObjectVal(vals), []supervisor.Process{{Name: "app", State: "STOPPED"}})
	if prior.GetAttr("in_sync").True() || prior.GetAttr("processes").Index(cty.StringVal("app")).AsString() != "STOPPED" {
		t.Fatalf("state %#v", prior)
	}
	plan := planSupervisor(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: prior})
	if p := plan.PlannedState; p.GetAttr("in_sync").IsKnown() || p.GetAttr("processes").IsKnown() {
		t.Errorf("stopped: planned %#v", p)
	}
	running := supervisorState(cty.ObjectVal(vals), []supervisor.Process{{Name: "app", State: "RUNNING"}})
	plan = planSupervisor(providers.PlanResourceChangeRequest{PriorState: running, ProposedNewState: running})
	if p := plan.PlannedState; !p.GetAttr("in_sync").RawEquals(cty.True) || !p.GetAttr("processes").RawEquals(running.GetAttr("processes")) {
		t.Errorf("running: planned %#v", plan.PlannedState)
	}
}
