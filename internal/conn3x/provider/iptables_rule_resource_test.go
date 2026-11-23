// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func TestIPTablesRuleValidate(t *testing.T) {
	in, tcp, ssh := cty.StringVal("INPUT"), cty.StringVal("tcp"), cty.StringVal("22")
	for name, attrs := range map[string]map[string]cty.Value{
		"both":       {"chain": in, "ip_version": cty.StringVal("both")},
		"position":   {"chain": in, "position": cty.StringVal("top")},
		"half num":   {"chain": in, "position": cty.StringVal("insert"), "rule_num": cty.NumberFloatVal(1.5)},
		"num append": {"chain": in, "rule_num": cty.NumberIntVal(2)},
		"v4 in v6":   {"chain": in, "ip_version": cty.StringVal("ipv6"), "source": cty.StringVal("10.0.0.0/8")},
		"on_remove":  {"chain": in, "on_remove": cty.StringVal("purge")},
	} {
		if diags := validateIPTablesRule(objFor(iptablesRuleSchema(), attrs)); !diags.HasErrors() {
			t.Errorf("%s: no error", name)
		}
	}
	ok := map[string]cty.Value{"chain": in, "protocol": tcp, "destination_port": ssh, "jump": cty.StringVal("ACCEPT"),
		"position": cty.StringVal("insert"), "rule_num": cty.NumberIntVal(1), "ip_version": cty.StringVal("ipv6"), "persist": cty.True,
		"ctstate": cty.ListVal([]cty.Value{cty.StringVal("NEW")}), "comment": cty.StringVal(`it's "ssh"`)}
	if diags := validateIPTablesRule(objFor(iptablesRuleSchema(), ok)); diags.HasErrors() {
		t.Error(diags.Err())
	}
}

// A changed spec replaces the rule, deleted by default; a changed
// position or persist only plans an update, and an in-sync rule plans
// nothing.
func TestIPTablesRulePlan(t *testing.T) {
	r := resourceTypes["conn3x_iptables_rule"]
	base := map[string]cty.Value{"chain": cty.StringVal("INPUT"), "protocol": cty.StringVal("tcp"), "destination_port": cty.StringVal("22"), "jump": cty.StringVal("ACCEPT"), "comment": cty.StringVal("ssh")}
	cfg := objFor(r.schema(), base)
	created := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
	if got := created.GetAttr("on_remove"); !got.RawEquals(cty.StringVal(onRemoveDelete)) {
		t.Errorf("on_remove defaults to %#v", got)
	}
	vals := withSync(created, true).AsValueMap()
	vals["id"] = cty.StringVal("x")
	prior := cty.ObjectVal(vals)

	same := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: cfg, Config: cfg})
	if len(same.RequiresReplace) != 0 || !same.PlannedState.GetAttr("in_sync").RawEquals(cty.True) {
		t.Errorf("unchanged: replace %v, planned %#v", same.RequiresReplace, same.PlannedState)
	}

	next := objFor(r.schema(), merge(map[string]cty.Value{"comment": cty.StringVal("ssh from anywhere")}, map[string]cty.Value{"chain": base["chain"], "protocol": base["protocol"], "destination_port": base["destination_port"], "jump": base["jump"]}))
	resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: next, Config: next})
	if len(resp.RequiresReplace) != 1 || !resp.RequiresReplace[0].Equals(cty.GetAttrPath("comment")) {
		t.Errorf("comment: RequiresReplace = %v", resp.RequiresReplace)
	}

	persist := objFor(r.schema(), merge(map[string]cty.Value{"persist": cty.True}, base))
	resp = r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: persist, Config: persist})
	if len(resp.RequiresReplace) != 0 || resp.PlannedState.GetAttr("in_sync").IsKnown() {
		t.Errorf("persist: replace %v, in_sync %#v", resp.RequiresReplace, resp.PlannedState.GetAttr("in_sync"))
	}
}
