// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func actionObj(attrs map[string]cty.Value) cty.Value {
	ty := serviceActionSchema().Block.ImpliedType()
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

func planAction(prior, cfg cty.Value) providers.PlanResourceChangeResponse {
	proposed := cfg
	if !prior.IsNull() {
		vals := cfg.AsValueMap()
		for _, n := range []string{"id", "action"} {
			if vals[n].IsNull() {
				vals[n] = prior.GetAttr(n)
			}
		}
		proposed = cty.ObjectVal(vals)
	}
	return planServiceAction(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: proposed, Config: cfg})
}

func TestServiceActionDefaultsToRestart(t *testing.T) {
	cfg := actionObj(map[string]cty.Value{"name": cty.StringVal("nginx"), "triggers": cty.StringVal("a")})
	planned := planAction(cty.NullVal(cfg.Type()), cfg).PlannedState
	if !planned.GetAttr("action").RawEquals(cty.StringVal("restart")) {
		t.Fatalf("action = %#v", planned.GetAttr("action"))
	}
}

func TestServiceActionReplacesWhenTriggersChange(t *testing.T) {
	prior := actionObj(map[string]cty.Value{"id": cty.StringVal("x"), "name": cty.StringVal("nginx"), "action": cty.StringVal("restart"), "triggers": cty.StringVal("a")})
	same := planAction(prior, actionObj(map[string]cty.Value{"name": cty.StringVal("nginx"), "triggers": cty.StringVal("a")}))
	if len(same.RequiresReplace) != 0 {
		t.Fatalf("unchanged triggers planned a replace: %v", same.RequiresReplace)
	}
	changed := planAction(prior, actionObj(map[string]cty.Value{"name": cty.StringVal("nginx"), "triggers": cty.StringVal("b")}))
	if len(changed.RequiresReplace) != 1 {
		t.Fatalf("changed triggers did not plan a replace: %v", changed.RequiresReplace)
	}
	unknown := planAction(prior, actionObj(map[string]cty.Value{"name": cty.StringVal("nginx"), "triggers": cty.UnknownVal(cty.String)}))
	if len(unknown.RequiresReplace) != 1 {
		t.Fatal("unknown triggers did not plan a replace")
	}
}

func TestServiceActionValidate(t *testing.T) {
	if !validateServiceAction(actionObj(map[string]cty.Value{"name": cty.StringVal("nginx"), "action": cty.StringVal("bounce")})).HasErrors() {
		t.Error("bad action accepted")
	}
}

// Handlers used to watch whole step objects and now watch their revisions.
// State from before has no revisions yet, so the first plan after upgrading
// must not fire every handler.
func TestServiceActionUpgradeDoesNotFire(t *testing.T) {
	step := cty.ObjectVal(map[string]cty.Value{"id": cty.StringVal("h:/etc/a"), "sha256": cty.StringVal("x")})
	prior := actionObj(map[string]cty.Value{
		"id": cty.StringVal("x"), "name": cty.StringVal("nginx"), "action": cty.StringVal("restart"),
		"triggers": cty.TupleVal([]cty.Value{step, cty.ObjectVal(map[string]cty.Value{"h/one": step})}),
	})
	now := cty.TupleVal([]cty.Value{cty.NullVal(cty.String), cty.ObjectVal(map[string]cty.Value{"h/one": cty.NullVal(cty.String)})})
	if resp := planAction(prior, actionObj(map[string]cty.Value{"name": cty.StringVal("nginx"), "triggers": now})); len(resp.RequiresReplace) != 0 {
		t.Fatalf("upgrade planned a replace: %v", resp.RequiresReplace)
	}
	changed := cty.TupleVal([]cty.Value{cty.UnknownVal(cty.String), cty.ObjectVal(map[string]cty.Value{"h/one": cty.NullVal(cty.String)})})
	if resp := planAction(prior, actionObj(map[string]cty.Value{"name": cty.StringVal("nginx"), "triggers": changed})); len(resp.RequiresReplace) != 1 {
		t.Fatal("a real change right after upgrading did not plan a replace")
	}
}

// Only a create or a replace runs the action; an in-place update records
// state without touching the host.
func TestServiceActionInPlaceUpdateRunsNothing(t *testing.T) {
	prior := actionObj(map[string]cty.Value{"id": cty.StringVal("x"), "name": cty.StringVal("nginx"), "action": cty.StringVal("restart"), "triggers": cty.StringVal("a")})
	planned := actionObj(map[string]cty.Value{"id": cty.StringVal("x"), "name": cty.StringVal("nginx"), "action": cty.StringVal("reload"), "triggers": cty.StringVal("a")})
	// The ssh block points at nothing, so any attempt to connect fails.
	resp := applyServiceAction(ctx, providers.ApplyResourceChangeRequest{PriorState: prior, PlannedState: planned, Config: planned})
	if resp.Diagnostics.HasErrors() {
		t.Fatalf("in-place update tried to reach the host: %v", resp.Diagnostics.Err())
	}
}

// Handlers with serial = true restarting the same unit share one lock, so
// k3s on three servers restarts one host at a time and keeps etcd quorum.
func TestServiceActionSerialLockIsPerUnit(t *testing.T) {
	if serialLock("k3s") != serialLock("k3s.service") {
		t.Error("k3s and k3s.service got different locks")
	}
	if serialLock("k3s") == serialLock("nginx") {
		t.Error("different units share a lock")
	}
}
