// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// eosDeviceConfig is a conn3x_eos_device data source's config on ssh.
func eosDeviceConfig(ssh cty.Value) cty.Value {
	vals := map[string]cty.Value{}
	for name, at := range eosDeviceSchema().Block.ImpliedType().AttributeTypes() {
		vals[name] = cty.NullVal(at)
	}
	vals["ssh"] = ssh
	return cty.ObjectVal(vals)
}

func TestEOSDeviceReadsFacts(t *testing.T) {
	f, ssh := newFakeEOS(t)
	f.show = map[string]string{
		"show version | json":           `{"modelName":"cEOSLab","version":"4.37.0F","serialNumber":"SN1","systemMacAddress":"00:1c:73:00:00:01"}`,
		"show hostname | json":          `{"hostname":"leaf1"}`,
		"show interfaces status | json": `{"interfaceStatuses":{"Ethernet2":{"linkStatus":"notconnect","description":""},"Ethernet1":{"linkStatus":"connected","description":"uplink"}}}`,
		"show lldp neighbors | json":    `{"lldpNeighbors":[{"port":"Ethernet1","neighborDevice":"spine1","neighborPort":"Ethernet3"}]}`,
	}
	resp := readEOSDevice(ctx, providers.ReadDataSourceRequest{Config: eosDeviceConfig(ssh)})
	if err := resp.Diagnostics.Err(); err != nil {
		t.Fatal(err)
	}
	s := resp.State
	if s.GetAttr("hostname").AsString() != "leaf1" || s.GetAttr("model").AsString() != "cEOSLab" || s.GetAttr("system_mac").AsString() != "00:1c:73:00:00:01" {
		t.Errorf("facts = %#v", s)
	}
	ifs := s.GetAttr("interfaces").AsValueSlice()
	if len(ifs) != 2 || ifs[0].GetAttr("name").AsString() != "Ethernet1" || ifs[0].GetAttr("status").AsString() != "connected" {
		t.Errorf("interfaces = %#v", ifs)
	}
	if nb := s.GetAttr("lldp_neighbors").AsValueSlice(); len(nb) != 1 || nb[0].GetAttr("neighbor_name").AsString() != "spine1" {
		t.Errorf("lldp_neighbors = %#v", nb)
	}

	// A switch that refuses the port and neighbour commands still has its
	// version facts, with both lists empty rather than null.
	delete(f.show, "show interfaces status | json")
	delete(f.show, "show lldp neighbors | json")
	resp = readEOSDevice(ctx, providers.ReadDataSourceRequest{Config: eosDeviceConfig(ssh)})
	if err := resp.Diagnostics.Err(); err != nil {
		t.Fatal(err)
	}
	if l := resp.State.GetAttr("interfaces"); l.IsNull() || l.LengthInt() != 0 || resp.State.GetAttr("lldp_neighbors").LengthInt() != 0 {
		t.Errorf("refused lists = %#v, %#v", l, resp.State.GetAttr("lldp_neighbors"))
	}

	// Without show version it isn't a switch Conn3x can read.
	delete(f.show, "show version | json")
	if resp := readEOSDevice(ctx, providers.ReadDataSourceRequest{Config: eosDeviceConfig(ssh)}); !strings.Contains(resp.Diagnostics.Err().Error(), "conn3x_eos_device") {
		t.Errorf("no show version: %v", resp.Diagnostics.Err())
	}
}

// A login that can't start is the ssh block's error, for the data source
// and for a step's refresh alike.
func TestEOSUnreachableIsAnSSHError(t *testing.T) {
	ssh := eosStep("conn3x_eos_vlan", nil, map[string]cty.Value{"private_key_file": cty.StringVal(filepath.Join(t.TempDir(), "missing"))}).GetAttr("ssh")
	if resp := readEOSDevice(ctx, providers.ReadDataSourceRequest{Config: eosDeviceConfig(ssh)}); !resp.Diagnostics.HasErrors() {
		t.Error("data source read on a missing key succeeded")
	}
	resp := eosVLANKind.read(ctx, providers.ReadResourceRequest{PriorState: vlanStep(10, "", ssh)})
	if !resp.Diagnostics.HasErrors() {
		t.Error("refresh on a missing key succeeded")
	}
	for name, apply := range map[string]func(providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse{"vlan": vlanApply, "commit": commitApply} {
		if err := create(apply, onSwitch(eosStep("conn3x_eos_"+name, map[string]cty.Value{"vlan_id": cty.NumberIntVal(10)}, nil), ssh)); err == nil {
			t.Errorf("%s apply on a missing key succeeded", name)
		}
	}
	removals := onSwitch(eosStep("conn3x_eos_removals", nil, nil), ssh)
	if err := destroy(removalsApply, removals); err == nil {
		t.Error("removals on a missing key succeeded")
	}
	if err := create(removalsApply, removals); err != nil {
		t.Errorf("creating the removals does nothing: %v", err)
	}
}

func TestEOSCommitAndRemovalsPlanAnID(t *testing.T) {
	for name, plan := range map[string]func(providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse{
		"commit": planEOSCommit, "removals": planEOSRemovals,
	} {
		v := eosStep("conn3x_eos_"+name, nil, nil)
		resp := plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(v.Type()), ProposedNewState: v, Config: v})
		if id := resp.PlannedState.GetAttr("id"); id.IsNull() || (id.IsKnown() && !strings.HasPrefix(id.AsString(), "leaf1")) {
			t.Errorf("%s: id = %#v", name, id)
		}
		if gone := plan(providers.PlanResourceChangeRequest{PriorState: v, ProposedNewState: cty.NullVal(v.Type())}); !gone.PlannedState.IsNull() {
			t.Errorf("%s: destroy planned %#v", name, gone.PlannedState)
		}
	}
}

// With backup_dir, the commit writes running-config as it was first, and a
// backup that fails commits nothing.
func TestEOSCommitBacksUpFirst(t *testing.T) {
	f, ssh := newFakeEOS(t, block{head: "hostname leaf1"})
	commitTo := func(dir string) cty.Value {
		return onSwitch(eosStep("conn3x_eos_commit", map[string]cty.Value{"id": cty.StringVal("eos-commit"), "backup_dir": cty.StringVal(dir)}, nil), ssh)
	}
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := create(vlanApply, vlanStep(10, "web", ssh)); err != nil {
		t.Fatal(err)
	}
	if err := create(commitApply, commitTo(filepath.Join(blocked, "sub"))); err == nil || !strings.Contains(err.Error(), "backup failed") {
		t.Fatalf("backup into a file: err = %v", err)
	}
	if _, commits, _, _ := f.state(); commits != 0 {
		t.Fatalf("%d commits after the backup failed", commits)
	}
	dir := t.TempDir()
	if err := create(commitApply, commitTo(dir)); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.cfg"))
	if len(files) != 1 {
		t.Fatalf("backups: %v", files)
	}
	if b, _ := os.ReadFile(files[0]); !strings.Contains(string(b), "hostname leaf1") || strings.Contains(string(b), "vlan 10") {
		t.Errorf("backup isn't the config from before:\n%s", b)
	}
}

func TestEOSRemovalsWithNothingToCommit(t *testing.T) {
	f, ssh := newFakeEOS(t, block{head: "vlan 10"})
	removals := onSwitch(eosStep("conn3x_eos_removals", map[string]cty.Value{"id": cty.StringVal("eos-removals")}, nil), ssh)
	if err := destroy(removalsApply, removals); err != nil {
		t.Fatal(err)
	}

	// A refused removal fails the circuit, and its removals commit nothing.
	f.refuse = "no vlan 10"
	if err := destroy(commitApply, commitFor(ssh, true)); err != nil {
		t.Fatal(err)
	}
	if err := destroy(vlanApply, vlanStep(10, "", ssh)); err == nil {
		t.Fatal("a refused removal succeeded")
	}
	if err := destroy(removalsApply, removals); err == nil || !strings.Contains(err.Error(), "nothing was committed") {
		t.Errorf("removals after a refusal: err = %v", err)
	}
	if running, commits, _, _ := f.state(); commits != 0 || !strings.Contains(running, "vlan 10") {
		t.Errorf("%d commits, running:\n%s", commits, running)
	}
}

func interfaceApply(req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return eosInterfaceKind.apply(ctx, req)
}

func interfaceStep(attrs map[string]cty.Value, ssh cty.Value) cty.Value {
	return onSwitch(eosStep("conn3x_eos_interface", attrs, nil), ssh)
}

// An interface step owns the settings it names, and on_remove = "delete"
// takes them back to EOS's defaults.
func TestEOSInterfaceOwnsItsSettings(t *testing.T) {
	f, ssh := newFakeEOS(t, block{head: "interface Ethernet1"})
	f.running = append(f.running, block{head: "interface Management0", kids: []string{"ip address " + ssh.GetAttr("host").AsString() + "/24"}})
	eth := interfaceStep(map[string]cty.Value{
		"name": cty.StringVal("Ethernet1"), "description": cty.StringVal("uplink"), "mode": cty.StringVal("trunk"),
		"allowed_vlans": cty.ListVal([]cty.Value{cty.NumberIntVal(10), cty.NumberIntVal(20)}), "mtu": cty.NumberIntVal(9000),
		"on_remove": cty.StringVal(onRemoveDelete),
	}, ssh)
	if err := create(interfaceApply, eth); err != nil {
		t.Fatal(err)
	}
	if err := create(commitApply, commitFor(ssh, true)); err != nil {
		t.Fatal(err)
	}
	running, _, _, _ := f.state()
	for _, want := range []string{"   description uplink\n", "   mtu 9000\n", "   switchport trunk allowed vlan 10,20\n"} {
		if !strings.Contains(running, want) {
			t.Errorf("running-config is missing %q:\n%s", want, running)
		}
	}
	if resp := eosInterfaceKind.read(ctx, providers.ReadResourceRequest{PriorState: eth}); resp.Diagnostics.HasErrors() || !resp.NewState.GetAttr("in_sync").True() {
		t.Errorf("read back: %#v, %v", resp.NewState.GetAttr("in_sync"), resp.Diagnostics.Err())
	}
	if err := destroy(interfaceApply, eth); err != nil {
		t.Fatal(err)
	}
	if running, _, _, _ := f.state(); strings.Contains(running, "uplink") || strings.Contains(running, "mtu 9000") || !strings.Contains(running, "interface Ethernet1\n") {
		t.Errorf("after the removal:\n%s", running)
	}

	// Shutting the interface Conn3x reaches the switch at would cut it off.
	mgmt := interfaceStep(map[string]cty.Value{"name": cty.StringVal("Management0"), "enabled": cty.False}, ssh)
	if err := create(interfaceApply, mgmt); err == nil || !strings.Contains(err.Error(), "cut it off") {
		t.Errorf("shutting the management interface: err = %v", err)
	}
}

func TestEOSInterfaceValidates(t *testing.T) {
	p, _ := New()
	vlans := func(ids ...int64) cty.Value {
		if len(ids) == 0 {
			return cty.ListValEmpty(cty.Number)
		}
		vs := make([]cty.Value, len(ids))
		for i, id := range ids {
			vs[i] = cty.NumberIntVal(id)
		}
		return cty.ListVal(vs)
	}
	for name, c := range map[string]struct {
		attrs map[string]cty.Value
		ok    bool
	}{
		"access port":            {map[string]cty.Value{"name": cty.StringVal("Ethernet1"), "mode": cty.StringVal("access"), "access_vlan": cty.NumberIntVal(10), "enabled": cty.True}, true},
		"bad name":               {map[string]cty.Value{"name": cty.StringVal("eth 1")}, false},
		"bad mode":               {map[string]cty.Value{"name": cty.StringVal("Ethernet1"), "mode": cty.StringVal("routed")}, false},
		"switchport on loopback": {map[string]cty.Value{"name": cty.StringVal("Loopback0"), "mode": cty.StringVal("access")}, false},
		"trunk with access_vlan": {map[string]cty.Value{"name": cty.StringVal("Ethernet1"), "mode": cty.StringVal("trunk"), "access_vlan": cty.NumberIntVal(10)}, false},
		"no allowed vlans":       {map[string]cty.Value{"name": cty.StringVal("Ethernet1"), "mode": cty.StringVal("trunk"), "allowed_vlans": vlans()}, false},
		"vlan 4095":              {map[string]cty.Value{"name": cty.StringVal("Ethernet1"), "mode": cty.StringVal("trunk"), "allowed_vlans": vlans(10, 4095)}, false},
		"bad on_remove":          {map[string]cty.Value{"name": cty.StringVal("Ethernet1"), "on_remove": cty.StringVal("purge")}, false},
	} {
		resp := p.ValidateResourceConfig(ctx, providers.ValidateResourceConfigRequest{TypeName: "conn3x_eos_interface", Config: eosStep("conn3x_eos_interface", c.attrs, nil)})
		if resp.Diagnostics.HasErrors() == c.ok {
			t.Errorf("%s: %v", name, resp.Diagnostics.Err())
		}
	}
}

func TestEOSUserRefusals(t *testing.T) {
	p, _ := New()
	for name, c := range map[string]struct {
		attrs map[string]cty.Value
		ok    bool
	}{
		"operator":                 {map[string]cty.Value{"name": cty.StringVal("ops"), "privilege": cty.NumberIntVal(1), "role": cty.StringVal("network-operator"), "nopassword": cty.False}, true},
		"privilege 16":             {map[string]cty.Value{"name": cty.StringVal("ops"), "privilege": cty.NumberIntVal(16)}, false},
		"nopassword with password": {map[string]cty.Value{"name": cty.StringVal("ops"), "nopassword": cty.True, "password_wo": cty.StringVal("pw")}, false},
	} {
		resp := p.ValidateResourceConfig(ctx, providers.ValidateResourceConfigRequest{TypeName: "conn3x_eos_user", Config: eosStep("conn3x_eos_user", c.attrs, nil)})
		if resp.Diagnostics.HasErrors() == c.ok {
			t.Errorf("%s: %v", name, resp.Diagnostics.Err())
		}
	}

	// Conn3x logs in as admin, so it won't delete admin.
	admin := eosStep("conn3x_eos_user", map[string]cty.Value{"name": cty.StringVal("admin"), "on_remove": cty.StringVal(onRemoveDelete)}, nil)
	resp := applyEOSUser(ctx, providers.ApplyResourceChangeRequest{PriorState: admin, PlannedState: cty.NullVal(admin.Type())})
	if err := resp.Diagnostics.Err(); err == nil || !strings.Contains(err.Error(), "won't delete that account") {
		t.Errorf("deleting the login account: %v", err)
	}

	// A planned password needs password_wo in the config at apply.
	planned := eosStep("conn3x_eos_user", map[string]cty.Value{"name": cty.StringVal("ops"), "password_hmac": cty.UnknownVal(cty.String)}, nil)
	resp = applyEOSUser(ctx, providers.ApplyResourceChangeRequest{PriorState: cty.NullVal(planned.Type()), PlannedState: planned, Config: cty.NullVal(planned.Type())})
	if err := resp.Diagnostics.Err(); err == nil || !strings.Contains(err.Error(), "didn't reach the apply") {
		t.Errorf("no password_wo at apply: %v", err)
	}
}

// An account with nopassword that the step doesn't ask for is an open
// login, and a refresh says so.
func TestEOSUserWarnsOfAnOpenLogin(t *testing.T) {
	_, ssh := newFakeEOS(t, block{head: "username ops privilege 1 nopassword"})
	ops := onSwitch(eosStep("conn3x_eos_user", map[string]cty.Value{"name": cty.StringVal("ops"), "on_remove": cty.StringVal(onRemoveDelete)}, nil), ssh)
	resp := eosUserKind.read(ctx, providers.ReadResourceRequest{PriorState: ops})
	if resp.Diagnostics.HasErrors() || len(resp.Diagnostics) != 1 || !strings.Contains(resp.Diagnostics[0].Description().Summary, "nopassword") {
		t.Errorf("diagnostics = %v", resp.Diagnostics)
	}
	vals := ops.AsValueMap()
	vals["nopassword"] = cty.True
	if resp := eosUserKind.read(ctx, providers.ReadResourceRequest{PriorState: cty.ObjectVal(vals)}); len(resp.Diagnostics) != 0 || !resp.NewState.GetAttr("in_sync").True() {
		t.Errorf("nopassword = true: in_sync %#v, %v", resp.NewState.GetAttr("in_sync"), resp.Diagnostics)
	}
}

func TestEOSStaticRouteValidate(t *testing.T) {
	r := resourceTypes["conn3x_eos_static_route"]
	hops := func(h ...string) cty.Value {
		var v []cty.Value
		for _, x := range h {
			v = append(v, cty.StringVal(x))
		}
		return cty.ListVal(v)
	}
	for name, attrs := range map[string]map[string]cty.Value{
		"host bits":    {"prefix": cty.StringVal("10.0.0.1/8"), "next_hops": hops("192.0.2.1")},
		"wrong family": {"prefix": cty.StringVal("10.0.0.0/8"), "next_hops": hops("2001:db8::1")},
	} {
		if diags := r.validate(objFor(r.schema(), attrs)); !diags.HasErrors() {
			t.Errorf("%s: no error", name)
		}
	}
	ok := map[string]cty.Value{"prefix": cty.StringVal("0.0.0.0/0"), "next_hops": hops("192.0.2.1")}
	if diags := r.validate(objFor(r.schema(), ok)); diags.HasErrors() {
		t.Error(diags.Err())
	}
}
