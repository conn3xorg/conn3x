// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"slices"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func TestJunosDeviceReadsFacts(t *testing.T) {
	f, ssh := newFakeJunos(t)
	f.show = map[string]string{"show version | display json | no-more": `show version | display json
{"software-information": [{"host-name": [{"data": "sw1"}], "product-model": [{"data": "ex9214"}], "junos-version": [{"data": "26.2R1.7"}]}]}`}
	cfg := map[string]cty.Value{}
	for name, at := range junosDeviceSchema().Block.ImpliedType().AttributeTypes() {
		cfg[name] = cty.NullVal(at)
	}
	cfg["ssh"] = ssh
	resp := readJunosDevice(ctx, providers.ReadDataSourceRequest{Config: cty.ObjectVal(cfg)})
	if err := resp.Diagnostics.Err(); err != nil {
		t.Fatal(err)
	}
	if s := resp.State; s.GetAttr("hostname").AsString() != "sw1" || s.GetAttr("model").AsString() != "ex9214" || s.GetAttr("version").AsString() != "26.2R1.7" {
		t.Errorf("facts = %#v", s)
	}
	f.mu.Lock()
	f.show = nil
	f.mu.Unlock()
	if resp := readJunosDevice(ctx, providers.ReadDataSourceRequest{Config: cty.ObjectVal(cfg)}); !resp.Diagnostics.HasErrors() {
		t.Error("a device that refuses show version read fine")
	}
	cfg["ssh"] = eosStep("conn3x_junos_commit", nil, map[string]cty.Value{"private_key_file": cty.StringVal(t.TempDir() + "/missing")}).GetAttr("ssh")
	if resp := readJunosDevice(ctx, providers.ReadDataSourceRequest{Config: cty.ObjectVal(cfg)}); !resp.Diagnostics.HasErrors() {
		t.Error("a login with a missing key read fine")
	}
}

func TestJunosValidates(t *testing.T) {
	p, _ := New()
	hops := cty.ListVal([]cty.Value{cty.StringVal("192.0.2.1")})
	for name, c := range map[string]struct {
		typeName string
		attrs    map[string]cty.Value
		ssh      map[string]cty.Value
		ok       bool
	}{
		"route":               {"conn3x_junos_static_route", map[string]cty.Value{"prefix": cty.StringVal("10.20.0.0/16"), "next_hops": hops, "preference": cty.NumberIntVal(5)}, map[string]cty.Value{"user": cty.StringVal("ops")}, true},
		"route host bits":     {"conn3x_junos_static_route", map[string]cty.Value{"prefix": cty.StringVal("10.20.0.1/16"), "next_hops": hops}, nil, false},
		"interface":           {"conn3x_junos_interface", map[string]cty.Value{"name": cty.StringVal("ge-0/0/1"), "enabled": cty.True, "mtu": cty.NumberIntVal(9000)}, nil, true},
		"bad interface":       {"conn3x_junos_interface", map[string]cty.Value{"name": cty.StringVal("ge 0")}, nil, false},
		"interface on_remove": {"conn3x_junos_interface", map[string]cty.Value{"name": cty.StringVal("ge-0/0/1"), "on_remove": cty.StringVal("purge")}, nil, false},
		"user":                {"conn3x_junos_user", map[string]cty.Value{"name": cty.StringVal("alice"), "class": cty.StringVal("operator")}, nil, true},
		"root user":           {"conn3x_junos_user", map[string]cty.Value{"name": cty.StringVal("root"), "class": cty.StringVal("operator")}, nil, false},
		"user on_remove":      {"conn3x_junos_user", map[string]cty.Value{"name": cty.StringVal("alice"), "class": cty.StringVal("operator"), "on_remove": cty.StringVal("purge")}, nil, false},
		"config on_remove":    {"conn3x_junos_config", map[string]cty.Value{"lines": cty.ListVal([]cty.Value{cty.StringVal("set system ntp server 192.0.2.1")}), "on_remove": cty.StringVal("purge")}, nil, false},
		"vlan without id":     {"conn3x_junos_vlan", map[string]cty.Value{"name": cty.StringVal("web"), "vlan_id": cty.NumberIntVal(0)}, nil, false},
		"root login":          {"conn3x_junos_vlan", map[string]cty.Value{"name": cty.StringVal("web"), "vlan_id": cty.NumberIntVal(10)}, map[string]cty.Value{"user": cty.StringVal("root")}, false},
		"agent":               {"conn3x_junos_vlan", map[string]cty.Value{"name": cty.StringVal("web"), "vlan_id": cty.NumberIntVal(10)}, map[string]cty.Value{"agent": cty.True}, false},
		"confirm_after 1h":    {"conn3x_junos_vlan", map[string]cty.Value{"name": cty.StringVal("web"), "vlan_id": cty.NumberIntVal(10)}, map[string]cty.Value{"confirm_after": cty.StringVal("1h")}, false},
	} {
		resp := p.ValidateResourceConfig(ctx, providers.ValidateResourceConfigRequest{TypeName: c.typeName, Config: eosStep(c.typeName, c.attrs, c.ssh)})
		if resp.Diagnostics.HasErrors() == c.ok {
			t.Errorf("%s: %v", name, resp.Diagnostics.Err())
		}
	}
}

func junosUserApply(req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyJunosUser(ctx, req)
}

// junos_user sends the hash of password_wo as encrypted-password, and the
// steps for routes and interfaces stage their statements alongside it.
func TestJunosUserRouteAndInterface(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	f, ssh := newFakeJunos(t)
	cfg := onSwitch(eosStep("conn3x_junos_user", map[string]cty.Value{
		"name": cty.StringVal("alice"), "class": cty.StringVal("operator"), "password_wo": cty.StringVal("Secret1"), "circuit": cty.StringVal("lab"),
	}, nil), ssh)
	null := cty.NullVal(cfg.Type())
	plan := planJunosUser(providers.PlanResourceChangeRequest{PriorState: null, ProposedNewState: cfg, Config: cfg})
	if err := plan.Diagnostics.Err(); err != nil {
		t.Fatal(err)
	}
	resp := applyJunosUser(ctx, providers.ApplyResourceChangeRequest{PriorState: null, PlannedState: plan.PlannedState, Config: cfg})
	if err := resp.Diagnostics.Err(); err != nil {
		t.Fatal(err)
	}
	user := resp.NewState
	route := onSwitch(eosStep("conn3x_junos_static_route", map[string]cty.Value{
		"prefix": cty.StringVal("10.20.0.0/16"), "next_hops": cty.ListVal([]cty.Value{cty.StringVal("192.0.2.1")}), "preference": cty.NumberIntVal(5), "circuit": cty.StringVal("lab"),
	}, nil), ssh)
	iface := onSwitch(eosStep("conn3x_junos_interface", map[string]cty.Value{
		"name": cty.StringVal("ge-0/0/1"), "description": cty.StringVal("uplink"), "enabled": cty.True, "mtu": cty.NumberIntVal(9000),
		"mode": cty.StringVal("trunk"), "allowed_vlans": cty.ListVal([]cty.Value{cty.StringVal("web")}), "circuit": cty.StringVal("lab"),
	}, nil), ssh)
	for kind, v := range map[*cliKind]cty.Value{&junosStaticRouteKind: route, &junosInterfaceKind: iface} {
		if err := create(func(req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
			return kind.apply(ctx, req)
		}, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := create(junosCommitApply, junosCommitFor("lab", ssh)); err != nil {
		t.Fatal(err)
	}
	running, commits, _ := f.state()
	if commits != 1 {
		t.Errorf("%d commits", commits)
	}
	for _, want := range []string{
		"set system login user alice class operator",
		"set routing-options static route 10.20.0.0/16 next-hop 192.0.2.1",
		"set routing-options static route 10.20.0.0/16 preference 5",
		"set interfaces ge-0/0/1 mtu 9000",
	} {
		if !slices.Contains(running, want) {
			t.Errorf("running is missing %q: %q", want, running)
		}
	}
	if slices.ContainsFunc(running, func(l string) bool { return strings.Contains(l, "Secret1") }) || !slices.ContainsFunc(running, func(l string) bool { return strings.Contains(l, `encrypted-password "$6$`) }) {
		t.Errorf("running: %q", running)
	}
	if read := junosUserKind.read(ctx, providers.ReadResourceRequest{PriorState: user}); read.Diagnostics.HasErrors() || !read.NewState.GetAttr("in_sync").True() {
		t.Errorf("read back: %#v, %v", read.NewState.GetAttr("in_sync"), read.Diagnostics.Err())
	}

	vals := user.AsValueMap()
	vals["name"], vals["on_remove"] = cty.StringVal("ops"), cty.StringVal(onRemoveDelete)
	if err := destroy(junosUserApply, cty.ObjectVal(vals)); err == nil || !strings.Contains(err.Error(), "won't delete that account") {
		t.Errorf("deleting the login: %v", err)
	}
	if err := create(junosUserApply, user); err == nil || !strings.Contains(err.Error(), "didn't reach the apply") {
		t.Errorf("no password_wo: %v", err)
	}
}
