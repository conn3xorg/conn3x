// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func npmObj(attrs map[string]cty.Value) cty.Value {
	ty := npmSchema().Block.ImpliedType()
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
	vals["name"] = cty.StringVal("left-pad")
	vals["path"] = cty.StringVal("/opt/app")
	for k, v := range attrs {
		vals[k] = v
	}
	return cty.ObjectVal(vals)
}

func TestNpmPlanReadsWhatRefreshRecorded(t *testing.T) {
	settled := map[string]cty.Value{"version": cty.StringVal("1.3.0"), "state": cty.StringVal("present"), "installed_version": cty.StringVal("1.3.0"), "id": cty.StringVal("x"), "on_remove": cty.StringVal("forget")}
	prior := npmObj(settled)
	plan := func(p, n cty.Value) providers.PlanResourceChangeResponse {
		return planNpm(providers.PlanResourceChangeRequest{PriorState: p, ProposedNewState: n})
	}
	if got := plan(prior, prior).PlannedState.GetAttr("installed_version"); !got.RawEquals(cty.StringVal("1.3.0")) {
		t.Fatalf("settled plan: %#v", got)
	}
	drifted := npmObj(map[string]cty.Value{"version": cty.StringVal("1.3.0"), "state": cty.StringVal("present"), "installed_version": cty.StringVal("1.2.0"), "id": cty.StringVal("x"), "on_remove": cty.StringVal("forget")})
	if got := plan(drifted, prior).PlannedState.GetAttr("installed_version"); got.IsKnown() {
		t.Fatalf("drifted plan: %#v", got)
	}
	moved := plan(prior, npmObj(map[string]cty.Value{"path": cty.StringVal("/opt/other"), "version": cty.StringVal("1.3.0"), "state": cty.StringVal("present"), "id": cty.StringVal("x"), "on_remove": cty.StringVal("forget")}))
	if len(moved.RequiresReplace) != 1 {
		t.Fatalf("moving the project should replace: %v", moved.RequiresReplace)
	}
	global := plan(prior, npmObj(map[string]cty.Value{"path": cty.NullVal(cty.String), "global": cty.True, "version": cty.StringVal("1.3.0"), "state": cty.StringVal("present"), "id": cty.StringVal("x"), "on_remove": cty.StringVal("forget")}))
	if len(global.RequiresReplace) != 2 {
		t.Fatalf("going global should replace: %v", global.RequiresReplace)
	}
}

func TestNpmValidate(t *testing.T) {
	for _, bad := range []map[string]cty.Value{
		{"name": cty.StringVal("left-pad@1")},
		{"path": cty.StringVal("app")},
		{"path": cty.NullVal(cty.String)},
		{"global": cty.True},
		{"version": cty.StringVal("^1")},
		{"state": cty.StringVal("installed")},
		{"on_remove": cty.StringVal("explode")},
	} {
		if !validateNpm(npmObj(bad)).HasErrors() {
			t.Errorf("accepted %v", bad)
		}
	}
	for _, good := range []map[string]cty.Value{
		nil,
		{"path": cty.NullVal(cty.String), "global": cty.True, "state": cty.StringVal("latest")},
	} {
		if d := validateNpm(npmObj(good)); d.HasErrors() {
			t.Error(d.Err())
		}
	}
}
