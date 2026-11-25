// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
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
		"conn3x_firewalld":     {"service": cty.StringVal("http"), "port": cty.StringVal("80/tcp")},
		"conn3x_ufw_rule":      {"action": cty.StringVal("allow"), "port": cty.StringVal("1000:2000")},
		"conn3x_iptables_rule": {"chain": cty.StringVal("INPUT"), "destination_port": cty.StringVal("22")},
	} {
		if diags := resourceTypes[rt].validate(objFor(resourceTypes[rt].schema(), cfg)); !diags.HasErrors() {
			t.Errorf("%s accepted %v", rt, cfg)
		}
	}
}

func TestFirewallConfirmAfter(t *testing.T) {
	for rt, cfg := range map[string]map[string]cty.Value{
		"conn3x_firewalld":     {"service": cty.StringVal("ssh")},
		"conn3x_ufw_rule":      {"action": cty.StringVal("allow"), "port": cty.StringVal("22/tcp")},
		"conn3x_iptables_rule": {"chain": cty.StringVal("INPUT"), "protocol": cty.StringVal("tcp"), "destination_port": cty.StringVal("22"), "jump": cty.StringVal("ACCEPT")},
	} {
		r := resourceTypes[rt]
		cfg["confirm_after"] = cty.StringVal("60s")
		if diags := r.validate(objFor(r.schema(), cfg)); diags.HasErrors() {
			t.Errorf("%s refused confirm_after 60s: %v", rt, diags.Err())
		}
		cfg["confirm_after"] = cty.StringVal("1s")
		if diags := r.validate(objFor(r.schema(), cfg)); !diags.HasErrors() {
			t.Errorf("%s accepted confirm_after 1s", rt)
		}
	}
}

// A ufw rule names a port or an application profile. app is in the id
// only when set, so a port rule's id is what it was before app existed,
// and changing the profile replaces the rule.
func TestUFWAppRule(t *testing.T) {
	r := resourceTypes["conn3x_ufw_rule"]
	plan := func(prior cty.Value, attrs map[string]cty.Value) providers.PlanResourceChangeResponse {
		cfg := objFor(r.schema(), attrs)
		if prior == cty.NilVal {
			prior = cty.NullVal(cfg.Type())
		}
		return r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: cfg, Config: cfg})
	}
	allow := cty.StringVal("allow")
	for want, attrs := range map[string]map[string]cty.Value{
		":ufw:allow:22/tcp:":                {"action": allow, "port": cty.StringVal("22/tcp")},
		":ufw:allow:::OpenSSH":              {"action": allow, "app": cty.StringVal("OpenSSH")},
		":ufw:allow::10.0.0.0/8:Nginx Full": {"action": allow, "app": cty.StringVal("Nginx Full"), "from": cty.StringVal("10.0.0.0/8")},
	} {
		if id := plan(cty.NilVal, attrs).PlannedState.GetAttr("id"); !id.IsKnown() || !strings.HasSuffix(id.AsString(), want) {
			t.Errorf("%v: id %#v, want it to end %q", attrs, id, want)
		}
	}
	prior := withSync(plan(cty.NilVal, map[string]cty.Value{"action": allow, "app": cty.StringVal("OpenSSH")}).PlannedState, true)
	resp := plan(prior, map[string]cty.Value{"action": allow, "app": cty.StringVal("Nginx Full")})
	if len(resp.RequiresReplace) != 1 || !resp.RequiresReplace[0].Equals(cty.GetAttrPath("app")) {
		t.Errorf("app change: RequiresReplace = %v", resp.RequiresReplace)
	}
	if resp := plan(prior, map[string]cty.Value{"action": allow, "app": cty.StringVal("OpenSSH")}); len(resp.RequiresReplace) != 0 || !resp.PlannedState.GetAttr("in_sync").RawEquals(cty.True) {
		t.Errorf("same app: RequiresReplace = %v, in_sync %#v", resp.RequiresReplace, resp.PlannedState.GetAttr("in_sync"))
	}
	if resp := plan(prior, map[string]cty.Value{"action": allow, "port": cty.StringVal("22/tcp")}); len(resp.RequiresReplace) == 0 {
		t.Error("app to port planned no replacement")
	}

	for _, bad := range []map[string]cty.Value{
		{"action": allow, "app": cty.StringVal("OpenSSH"), "port": cty.StringVal("22/tcp")},
		{"action": allow, "app": cty.StringVal("OpenSSH'; reboot; '")},
		{"action": allow},
	} {
		if diags := r.validate(objFor(r.schema(), bad)); !diags.HasErrors() {
			t.Errorf("accepted %v", bad)
		}
	}
	if diags := r.validate(objFor(r.schema(), map[string]cty.Value{"action": allow, "app": cty.StringVal("Nginx Full")})); diags.HasErrors() {
		t.Errorf("refused app Nginx Full: %v", diags.Err())
	}
}
