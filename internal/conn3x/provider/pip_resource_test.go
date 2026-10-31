// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func pipObj(attrs map[string]cty.Value) cty.Value {
	ty := pipSchema().Block.ImpliedType()
	vals := map[string]cty.Value{}
	for name, at := range ty.AttributeTypes() {
		vals[name] = cty.NullVal(at)
	}
	sshVals := map[string]cty.Value{}
	for name, at := range ty.AttributeType("ssh").AttributeTypes() {
		sshVals[name] = cty.NullVal(at)
	}
	sshVals["host"] = cty.StringVal("203.0.113.10")
	vals["ssh"] = cty.ObjectVal(sshVals)
	vals["name"] = cty.StringVal("six")
	vals["venv"] = cty.StringVal("/opt/v")
	for k, v := range attrs {
		vals[k] = v
	}
	return cty.ObjectVal(vals)
}

func TestPipPlanReadsWhatRefreshRecorded(t *testing.T) {
	prior := pipObj(map[string]cty.Value{"version": cty.StringVal("1.16.0"), "state": cty.StringVal("present"), "installed_version": cty.StringVal("1.16.0"), "id": cty.StringVal("x"), "on_remove": cty.StringVal("forget")})
	plan := func(p, n cty.Value) providers.PlanResourceChangeResponse {
		return planPip(providers.PlanResourceChangeRequest{PriorState: p, ProposedNewState: n})
	}
	if got := plan(prior, prior).PlannedState.GetAttr("installed_version"); !got.RawEquals(cty.StringVal("1.16.0")) {
		t.Fatalf("settled plan: %#v", got)
	}
	drifted := pipObj(map[string]cty.Value{"version": cty.StringVal("1.16.0"), "state": cty.StringVal("present"), "installed_version": cty.StringVal("1.15.0"), "id": cty.StringVal("x"), "on_remove": cty.StringVal("forget")})
	if got := plan(drifted, prior).PlannedState.GetAttr("installed_version"); got.IsKnown() {
		t.Fatalf("drifted plan: %#v", got)
	}
	moved := plan(prior, pipObj(map[string]cty.Value{"venv": cty.StringVal("/opt/w"), "version": cty.StringVal("1.16.0"), "state": cty.StringVal("present"), "id": cty.StringVal("x"), "on_remove": cty.StringVal("forget")}))
	if len(moved.RequiresReplace) != 1 {
		t.Fatalf("moving the venv should replace: %v", moved.RequiresReplace)
	}
}

func TestPipValidate(t *testing.T) {
	for _, bad := range []map[string]cty.Value{
		{"name": cty.StringVal("six==1")},
		{"venv": cty.StringVal("venv")},
		{"user": cty.StringVal("no such user")},
		{"state": cty.StringVal("forcereinstall")},
		{"on_remove": cty.StringVal("explode")},
	} {
		if !validatePip(pipObj(bad)).HasErrors() {
			t.Errorf("accepted %v", bad)
		}
	}
	if d := validatePip(pipObj(nil)); d.HasErrors() {
		t.Error(d.Err())
	}
}
