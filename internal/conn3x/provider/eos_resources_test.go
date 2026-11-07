// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"strings"
	"testing"

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
