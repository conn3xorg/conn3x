// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// Changing a rule's port must close the old port, so firewall rules default
// to on_remove = "delete" and a changed port replaces the rule.
func TestFirewallRulesCloseWhatTheyReplace(t *testing.T) {
	for rt, attrs := range map[string][2]map[string]cty.Value{
		"conn3x_firewalld": {{"port": cty.StringVal("8080/tcp")}, {"port": cty.StringVal("8443/tcp")}},
		"conn3x_ufw_rule":  {{"action": cty.StringVal("allow"), "port": cty.StringVal("8080/tcp")}, {"action": cty.StringVal("allow"), "port": cty.StringVal("8443/tcp")}},
	} {
		r := resourceTypes[rt]
		cfg := objFor(r.schema(), attrs[0])
		created := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
		if got := created.GetAttr("on_remove"); !got.RawEquals(cty.StringVal(onRemoveDelete)) {
			t.Errorf("%s: on_remove defaults to %#v", rt, got)
		}
		prior := withSync(created, true)
		vals := prior.AsValueMap()
		vals["id"] = cty.StringVal("x")
		prior = cty.ObjectVal(vals)
		next := objFor(r.schema(), attrs[1])
		resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: next, Config: next})
		if len(resp.RequiresReplace) != 1 || !resp.RequiresReplace[0].Equals(cty.GetAttrPath("port")) {
			t.Errorf("%s: RequiresReplace = %v", rt, resp.RequiresReplace)
		}
		kept := objFor(r.schema(), map[string]cty.Value{"on_remove": cty.StringVal(onRemoveForget)})
		kept = cty.ObjectVal(merge(kept.AsValueMap(), attrs[0]))
		if got := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: kept, Config: kept}).PlannedState.GetAttr("on_remove"); !got.RawEquals(cty.StringVal(onRemoveForget)) {
			t.Errorf("%s: an explicit on_remove was overridden: %#v", rt, got)
		}
	}
}

func merge(a, b map[string]cty.Value) map[string]cty.Value {
	for k, v := range b {
		a[k] = v
	}
	return a
}

func TestFirewallValidate(t *testing.T) {
	for rt, cfg := range map[string]map[string]cty.Value{
		"conn3x_firewalld": {"service": cty.StringVal("http"), "port": cty.StringVal("80/tcp")},
		"conn3x_ufw_rule":  {"action": cty.StringVal("allow"), "port": cty.StringVal("1000:2000")},
	} {
		if diags := resourceTypes[rt].validate(objFor(resourceTypes[rt].schema(), cfg)); !diags.HasErrors() {
			t.Errorf("%s accepted %v", rt, cfg)
		}
	}
}
