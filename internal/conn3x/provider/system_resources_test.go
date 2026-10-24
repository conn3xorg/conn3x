// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func objFor(schema providers.Schema, attrs map[string]cty.Value) cty.Value {
	ty := schema.Block.ImpliedType()
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

// A host has one hostname and one time zone, so changing either is an
// update in place, never a replacement.
func TestSingletonPlanUpdatesInPlace(t *testing.T) {
	for _, rt := range []string{"conn3x_hostname", "conn3x_timezone"} {
		schema := resourceTypes[rt].schema()
		prior := objFor(schema, map[string]cty.Value{
			"id": cty.StringVal("203.0.113.10:" + rt[len("conn3x_"):]), "name": cty.StringVal("old"), "in_sync": cty.True,
		})
		cfg := objFor(schema, map[string]cty.Value{"name": cty.StringVal("new")})
		resp := resourceTypes[rt].plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: cfg, Config: cfg})
		if len(resp.RequiresReplace) != 0 {
			t.Errorf("%s: name change requires replace: %v", rt, resp.RequiresReplace)
		}
		if got := resp.PlannedState.GetAttr("id"); !got.RawEquals(prior.GetAttr("id")) {
			t.Errorf("%s: id = %#v", rt, got)
		}
		if resp.PlannedState.GetAttr("in_sync").IsKnown() {
			t.Errorf("%s: a changed name must plan an update", rt)
		}

		same := resourceTypes[rt].plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: prior, Config: prior})
		if !same.PlannedState.GetAttr("in_sync").RawEquals(cty.True) {
			t.Errorf("%s: unchanged and in sync must plan nothing", rt)
		}
	}
}

func TestSysctlNameChangeReplaces(t *testing.T) {
	schema := sysctlSchema()
	prior := objFor(schema, map[string]cty.Value{
		"id": cty.StringVal("203.0.113.10:sysctl:vm.swappiness"), "name": cty.StringVal("vm.swappiness"),
		"value": cty.StringVal("10"), "on_remove": cty.StringVal("forget"), "in_sync": cty.True,
	})
	cfg := objFor(schema, map[string]cty.Value{"name": cty.StringVal("vm.overcommit_memory"), "value": cty.StringVal("10")})
	if resp := planSysctl(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: cfg, Config: cfg}); len(resp.RequiresReplace) != 1 {
		t.Fatalf("RequiresReplace = %v", resp.RequiresReplace)
	}
}

func TestSystemValidate(t *testing.T) {
	for rt, cfg := range map[string]map[string]cty.Value{
		"conn3x_sysctl":   {"name": cty.StringVal("ip_forward"), "value": cty.StringVal("1")},
		"conn3x_hostname": {"name": cty.StringVal("web_1")},
		"conn3x_timezone": {"name": cty.StringVal("../etc/shadow")},
	} {
		if diags := resourceTypes[rt].validate(objFor(resourceTypes[rt].schema(), cfg)); !diags.HasErrors() {
			t.Errorf("%s accepted %v", rt, cfg)
		}
	}
}
