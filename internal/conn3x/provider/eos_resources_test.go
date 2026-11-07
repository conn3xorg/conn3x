// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func eosStep(typeName string, attrs map[string]cty.Value, sshAttrs map[string]cty.Value) cty.Value {
	ty := resourceSchemas()[typeName].Block.ImpliedType()
	vals := map[string]cty.Value{}
	for name, at := range ty.AttributeTypes() {
		vals[name] = cty.NullVal(at)
	}
	for k, v := range attrs {
		vals[k] = v
	}
	sshTy := ty.AttributeType("ssh")
	sv := map[string]cty.Value{}
	for name, at := range sshTy.AttributeTypes() {
		sv[name] = cty.NullVal(at)
	}
	sv["host"] = cty.StringVal("leaf1")
	sv["user"] = cty.StringVal("admin")
	for k, v := range sshAttrs {
		sv[k] = v
	}
	vals["ssh"] = cty.ObjectVal(sv)
	return cty.ObjectVal(vals)
}

func TestEOSRejectsShellOnlySSHSettings(t *testing.T) {
	p, _ := New()
	vlan := map[string]cty.Value{"vlan_id": cty.NumberIntVal(10)}
	ok := p.ValidateResourceConfig(context.Background(), providers.ValidateResourceConfigRequest{TypeName: "conn3x_eos_vlan", Config: eosStep("conn3x_eos_vlan", vlan, nil)})
	if ok.Diagnostics.HasErrors() {
		t.Fatal(ok.Diagnostics.Err())
	}
	for attr, v := range map[string]cty.Value{"agent": cty.True, "become": cty.True, "become_password_file": cty.StringVal("pw")} {
		resp := p.ValidateResourceConfig(context.Background(), providers.ValidateResourceConfigRequest{
			TypeName: "conn3x_eos_vlan", Config: eosStep("conn3x_eos_vlan", vlan, map[string]cty.Value{attr: v}),
		})
		if !resp.Diagnostics.HasErrors() || !strings.Contains(resp.Diagnostics.Err().Error(), "EOS") {
			t.Errorf("%s: %v", attr, resp.Diagnostics.Err())
		}
	}
	off := p.ValidateResourceConfig(context.Background(), providers.ValidateResourceConfigRequest{
		TypeName: "conn3x_eos_vlan", Config: eosStep("conn3x_eos_vlan", vlan, map[string]cty.Value{"agent": cty.False}),
	})
	if off.Diagnostics.HasErrors() {
		t.Errorf("agent = false is fine: %v", off.Diagnostics.Err())
	}
}

func TestEOSConfigValidates(t *testing.T) {
	p, _ := New()
	lines := func(l ...string) cty.Value {
		vs := make([]cty.Value, len(l))
		for i, s := range l {
			vs[i] = cty.StringVal(s)
		}
		return cty.ListVal(vs)
	}
	for name, attrs := range map[string]map[string]cty.Value{
		"block without parents": {"lines": lines("hostname x"), "match": cty.StringVal("block")},
		"end in lines":          {"parents": lines("interface Ethernet1"), "lines": lines("end")},
		"bad on_remove":         {"lines": lines("hostname x"), "on_remove": cty.StringVal("purge")},
	} {
		resp := p.ValidateResourceConfig(context.Background(), providers.ValidateResourceConfigRequest{TypeName: "conn3x_eos_config", Config: eosStep("conn3x_eos_config", attrs, nil)})
		if !resp.Diagnostics.HasErrors() {
			t.Errorf("%s: no error", name)
		}
	}
	host := p.ValidateResourceConfig(context.Background(), providers.ValidateResourceConfigRequest{TypeName: "conn3x_eos_hostname",
		Config: eosStep("conn3x_eos_hostname", map[string]cty.Value{"name": cty.StringVal("leaf 1")}, nil)})
	if !host.Diagnostics.HasErrors() {
		t.Error("a hostname with a space should fail")
	}
}

func TestEOSVLANPlansDeleteByDefault(t *testing.T) {
	cfg := eosStep("conn3x_eos_vlan", map[string]cty.Value{"vlan_id": cty.NumberIntVal(10)}, nil)
	ty := cfg.Type()
	resp := eosVLANKind.plan(providers.PlanResourceChangeRequest{
		TypeName: "conn3x_eos_vlan", Config: cfg, ProposedNewState: cfg, PriorState: cty.NullVal(ty),
	})
	if resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	if got := resp.PlannedState.GetAttr("on_remove"); got.AsString() != onRemoveDelete {
		t.Errorf("on_remove = %v", got)
	}
}

func TestEOSConfigPlansWithParents(t *testing.T) {
	parents := cty.ListVal([]cty.Value{cty.StringVal("router bgp 65000"), cty.StringVal("address-family ipv4")})
	cfg := eosStep("conn3x_eos_config", map[string]cty.Value{
		"parents": parents,
		"lines":   cty.ListVal([]cty.Value{cty.StringVal("neighbor 10.0.0.1 activate")}),
	}, nil)
	resp := eosConfigKind.plan(providers.PlanResourceChangeRequest{
		TypeName: "conn3x_eos_config", Config: cfg, ProposedNewState: cfg, PriorState: cty.NullVal(cfg.Type()),
	})
	if resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	if id := resp.PlannedState.GetAttr("id"); !id.IsKnown() {
		t.Error("a known parents list should give a known id")
	}

	unknown := eosStep("conn3x_eos_config", map[string]cty.Value{
		"parents": cty.ListVal([]cty.Value{cty.UnknownVal(cty.String)}),
		"lines":   cty.ListVal([]cty.Value{cty.StringVal("description x")}),
	}, nil)
	resp = eosConfigKind.plan(providers.PlanResourceChangeRequest{
		TypeName: "conn3x_eos_config", Config: unknown, ProposedNewState: unknown, PriorState: cty.NullVal(unknown.Type()),
	})
	if resp.Diagnostics.HasErrors() || resp.PlannedState.GetAttr("id").IsKnown() {
		t.Errorf("a parent known only at apply: id %#v, %v", resp.PlannedState.GetAttr("id"), resp.Diagnostics.Err())
	}
}

func TestConfirmAfterIsChecked(t *testing.T) {
	p, _ := New()
	vlan := map[string]cty.Value{"vlan_id": cty.NumberIntVal(10)}
	for v, ok := range map[string]bool{"5s": true, "30s": true, "3m": true, "4s": false, "4m": false, "soon": false} {
		resp := p.ValidateResourceConfig(context.Background(), providers.ValidateResourceConfigRequest{
			TypeName: "conn3x_eos_vlan", Config: eosStep("conn3x_eos_vlan", vlan, map[string]cty.Value{"confirm_after": cty.StringVal(v)}),
		})
		if resp.Diagnostics.HasErrors() == ok {
			t.Errorf("confirm_after = %q: %v", v, resp.Diagnostics.Err())
		}
	}
	file := eosStep("conn3x_file", map[string]cty.Value{"path": cty.StringVal("/etc/motd"), "content": cty.StringVal("hi")}, map[string]cty.Value{"confirm_after": cty.StringVal("30s")})
	resp := p.ValidateResourceConfig(context.Background(), providers.ValidateResourceConfigRequest{TypeName: "conn3x_file", Config: file})
	if !resp.Diagnostics.HasErrors() || !strings.Contains(resp.Diagnostics.Err().Error(), "eos_") {
		t.Errorf("confirm_after on a file step: %v", resp.Diagnostics.Err())
	}
	if got := confirmAfter(eosStep("conn3x_eos_vlan", vlan, nil).GetAttr("ssh")); got != 30*time.Second {
		t.Errorf("default = %s", got)
	}
}
