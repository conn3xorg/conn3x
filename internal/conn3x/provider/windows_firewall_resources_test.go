// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func TestWinFirewallRuleValidate(t *testing.T) {
	r := resourceTypes["conn3x_windows_firewall_rule"]
	list := func(s ...string) cty.Value {
		var v []cty.Value
		for _, x := range s {
			v = append(v, cty.StringVal(x))
		}
		return cty.ListVal(v)
	}
	if d := r.validate(objFor(r.schema(), map[string]cty.Value{
		"name": cty.StringVal("web"), "protocol": cty.StringVal("tcp"), "local_ports": list("443"), "remote_addresses": list("10.0.0.0/8"),
	})); d.HasErrors() {
		t.Fatal(d.Err())
	}
	for name, a := range map[string]map[string]cty.Value{
		"wildcard":        {"name": cty.StringVal("web*")},
		"ports, no proto": {"name": cty.StringVal("a"), "local_ports": list("80")},
		"blocks ssh":      {"name": cty.StringVal("a"), "action": cty.StringVal("block")},
		"blocks tcp 22":   {"name": cty.StringVal("a"), "action": cty.StringVal("block"), "protocol": cty.StringVal("tcp"), "local_ports": list("20-30")},
		"bad on_remove":   {"name": cty.StringVal("a"), "on_remove": cty.StringVal("purge")},
		"blocks every v4": {"name": cty.StringVal("a"), "action": cty.StringVal("block"), "remote_addresses": list("0.0.0.0/0", "::/0")},
		"blocks a range":  {"name": cty.StringVal("a"), "action": cty.StringVal("block"), "remote_addresses": list("0.0.0.0-255.255.255.255")},
		"blocks subnet":   {"name": cty.StringVal("a"), "action": cty.StringVal("block"), "remote_addresses": list("LocalSubnet")},
	} {
		if d := r.validate(objFor(r.schema(), a)); !d.HasErrors() {
			t.Errorf("%s: accepted", name)
		}
	}
	// Blocking 22 is fine when Conn3x comes in on another port.
	c := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("a"), "action": cty.StringVal("block"), "protocol": cty.StringVal("tcp"), "local_ports": list("22")}).AsValueMap()
	ssh := c["ssh"].AsValueMap()
	ssh["port"] = cty.NumberIntVal(2222)
	c["ssh"] = cty.ObjectVal(ssh)
	if d := r.validate(cty.ObjectVal(c)); d.HasErrors() {
		t.Error(d.Err())
	}
}

func TestWinFirewallRuleDeletesByDefault(t *testing.T) {
	r := resourceTypes["conn3x_windows_firewall_rule"]
	c := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("web")})
	p := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(c.Type()), ProposedNewState: c, Config: c}).PlannedState
	if p.GetAttr("on_remove").AsString() != "delete" {
		t.Errorf("on_remove = %#v", p.GetAttr("on_remove"))
	}
}

// A rule's name ignores case on Windows: a case change is no replacement.
func TestWinFirewallRuleCaseIsNotReplace(t *testing.T) {
	r := resourceTypes["conn3x_windows_firewall_rule"]
	c := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("Web")})
	p := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(c.Type()), ProposedNewState: c, Config: c}).PlannedState
	vals := p.AsValueMap()
	vals["revision"], vals["in_sync"] = cty.StringVal("r"), cty.True
	prior := cty.ObjectVal(vals)
	lower := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("web")})
	if resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: lower, Config: lower}); len(resp.RequiresReplace) != 0 {
		t.Errorf("replaces: %v", resp.RequiresReplace)
	}
}
