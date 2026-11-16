// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"slices"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
	"github.com/opentofu/opentofu/internal/providers"
)

// netVyOS is a fakeVyOS router logged in to as vyos, and its ssh block.
func netVyOS(t *testing.T, running ...string) (*fakeVyOS, cty.Value) {
	t.Helper()
	s := sshtest.New(t)
	f := &fakeVyOS{running: running}
	s.SetExec(func(cmd string, stdin []byte) (string, int) {
		f.mu.Lock()
		version := f.version
		f.mu.Unlock()
		if cmd == "/opt/vyatta/bin/vyatta-op-cmd-wrapper show version" && version != "" {
			return "Version:          " + version + "\nRelease train:    current\n", 0
		}
		return f.run(cmd, stdin)
	})
	t.Cleanup(func() { _ = FinishEOS() })
	return f, eosStep("conn3x_vyos_commit", nil, map[string]cty.Value{
		"host": cty.StringVal(s.Host), "port": cty.NumberIntVal(int64(s.Port)), "user": cty.StringVal("vyos"),
		"private_key_file": cty.StringVal(s.KeyFile(t)), "known_hosts_file": cty.StringVal(s.KnownHosts(t)),
		"confirm_after": cty.StringVal("10ms"),
	}).GetAttr("ssh")
}

func TestVyOSDeviceReadsFacts(t *testing.T) {
	f, ssh := netVyOS(t, "set system host-name r1")
	f.version = "2026.11.13-0016-rolling"
	cfg := map[string]cty.Value{}
	for name, at := range vyosDeviceSchema().Block.ImpliedType().AttributeTypes() {
		cfg[name] = cty.NullVal(at)
	}
	cfg["ssh"] = ssh
	resp := readVyOSDevice(ctx, providers.ReadDataSourceRequest{Config: cty.ObjectVal(cfg)})
	if err := resp.Diagnostics.Err(); err != nil {
		t.Fatal(err)
	}
	if h, v := resp.State.GetAttr("hostname").AsString(), resp.State.GetAttr("version").AsString(); h != "r1" || v != f.version {
		t.Errorf("hostname %q, version %q", h, v)
	}
	f.mu.Lock()
	f.version = ""
	f.mu.Unlock()
	if resp := readVyOSDevice(ctx, providers.ReadDataSourceRequest{Config: cty.ObjectVal(cfg)}); !resp.Diagnostics.HasErrors() {
		t.Error("a router that doesn't say its version read fine")
	}
	cfg["ssh"] = eosStep("conn3x_vyos_commit", nil, map[string]cty.Value{"private_key_file": cty.StringVal(t.TempDir() + "/missing")}).GetAttr("ssh")
	if resp := readVyOSDevice(ctx, providers.ReadDataSourceRequest{Config: cty.ObjectVal(cfg)}); !resp.Diagnostics.HasErrors() {
		t.Error("a login with a missing key read fine")
	}
}

func TestVyOSValidates(t *testing.T) {
	p, _ := New()
	for name, c := range map[string]struct {
		typeName string
		attrs    map[string]cty.Value
		ssh      map[string]cty.Value
		ok       bool
	}{
		"interface":           {"conn3x_vyos_interface", map[string]cty.Value{"name": cty.StringVal("eth1"), "enabled": cty.True, "addresses": cty.ListVal([]cty.Value{cty.StringVal("192.0.2.1/24")})}, nil, true},
		"bad interface":       {"conn3x_vyos_interface", map[string]cty.Value{"name": cty.StringVal("eth 1")}, nil, false},
		"route":               {"conn3x_vyos_static_route", map[string]cty.Value{"prefix": cty.StringVal("10.0.0.0/8"), "distance": cty.NumberIntVal(10), "next_hops": cty.ListVal([]cty.Value{cty.StringVal("192.0.2.1")})}, nil, true},
		"bad route":           {"conn3x_vyos_static_route", map[string]cty.Value{"prefix": cty.StringVal("10.0.0.0")}, nil, false},
		"user":                {"conn3x_vyos_user", map[string]cty.Value{"name": cty.StringVal("alice"), "full_name": cty.StringVal("Alice")}, nil, true},
		"root user":           {"conn3x_vyos_user", map[string]cty.Value{"name": cty.StringVal("root")}, nil, false},
		"quote in full_name":  {"conn3x_vyos_user", map[string]cty.Value{"name": cty.StringVal("alice"), "full_name": cty.StringVal(`A "B"`)}, nil, false},
		"config on_remove":    {"conn3x_vyos_config", map[string]cty.Value{"lines": cty.ListVal([]cty.Value{cty.StringVal("set system ntp")}), "on_remove": cty.StringVal("purge")}, nil, false},
		"agent":               {"conn3x_vyos_hostname", map[string]cty.Value{"name": cty.StringVal("r1")}, map[string]cty.Value{"agent": cty.True}, false},
		"become":              {"conn3x_vyos_hostname", map[string]cty.Value{"name": cty.StringVal("r1")}, map[string]cty.Value{"become": cty.True}, false},
		"confirm_after 1h":    {"conn3x_vyos_hostname", map[string]cty.Value{"name": cty.StringVal("r1")}, map[string]cty.Value{"confirm_after": cty.StringVal("1h")}, false},
		"confirm_after 30s":   {"conn3x_vyos_hostname", map[string]cty.Value{"name": cty.StringVal("r1")}, map[string]cty.Value{"confirm_after": cty.StringVal("30s"), "agent": cty.False}, true},
		"password and a file": {"conn3x_vyos_hostname", map[string]cty.Value{"name": cty.StringVal("r1")}, map[string]cty.Value{"become_password_file": cty.StringVal("pw")}, false},
	} {
		resp := p.ValidateResourceConfig(ctx, providers.ValidateResourceConfigRequest{TypeName: c.typeName, Config: eosStep(c.typeName, c.attrs, c.ssh)})
		if resp.Diagnostics.HasErrors() == c.ok {
			t.Errorf("%s: %v", name, resp.Diagnostics.Err())
		}
	}
}

func vyosUserApply(req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyVyOSUser(ctx, req)
}

// vyos_user sends the hash of password_wo, never the password, and a
// refresh finds the account in sync by the HMAC alone.
func TestVyOSUserSetsAPassword(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	f, ssh := netVyOS(t, "set system config-management commit-confirm action reload")
	attrs := map[string]cty.Value{
		"name": cty.StringVal("alice"), "password_wo": cty.StringVal("Secret1"),
		"ssh_keys": cty.ListVal([]cty.Value{cty.StringVal("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA alice@laptop")}),
	}
	cfg := onSwitch(eosStep("conn3x_vyos_user", attrs, nil), ssh)
	null := cty.NullVal(cfg.Type())
	plan := planVyOSUser(providers.PlanResourceChangeRequest{PriorState: null, ProposedNewState: cfg, Config: cfg})
	if err := plan.Diagnostics.Err(); err != nil {
		t.Fatal(err)
	}
	resp := applyVyOSUser(ctx, providers.ApplyResourceChangeRequest{PriorState: null, PlannedState: plan.PlannedState, Config: cfg})
	if err := resp.Diagnostics.Err(); err != nil {
		t.Fatal(err)
	}
	state := resp.NewState
	if !state.GetAttr("password_wo").IsNull() || !strings.HasPrefix(state.GetAttr("password_hmac").AsString(), passwordTag) {
		t.Errorf("state: password_wo %#v, password_hmac %#v", state.GetAttr("password_wo"), state.GetAttr("password_hmac"))
	}
	if err := create(func(req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
		return applyCLICommit(vyosPlatform)(ctx, req)
	}, onSwitch(eosStep("conn3x_vyos_commit", map[string]cty.Value{"id": cty.StringVal("c")}, nil), ssh)); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	running := slices.Clone(f.running)
	f.mu.Unlock()
	if !slices.ContainsFunc(running, func(l string) bool { return strings.Contains(l, "encrypted-password '$6$") }) || slices.ContainsFunc(running, func(l string) bool { return strings.Contains(l, "Secret1") }) {
		t.Errorf("running: %q", running)
	}
	read := vyosUserKind.read(ctx, providers.ReadResourceRequest{PriorState: state})
	if read.Diagnostics.HasErrors() || !read.NewState.GetAttr("in_sync").True() {
		t.Errorf("read back: %#v, %v", read.NewState.GetAttr("in_sync"), read.Diagnostics.Err())
	}

	// Conn3x won't delete the account it logs in as, nor apply a password
	// that didn't reach the apply.
	vals := state.AsValueMap()
	vals["name"] = cty.StringVal("vyos")
	if err := destroy(vyosUserApply, cty.ObjectVal(vals)); err == nil || !strings.Contains(err.Error(), "won't delete that account") {
		t.Errorf("deleting the login: %v", err)
	}
	if err := create(vyosUserApply, state); err == nil || !strings.Contains(err.Error(), "didn't reach the apply") {
		t.Errorf("no password_wo: %v", err)
	}
	if err := destroy(vyosUserApply, state); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if slices.ContainsFunc(f.running, func(l string) bool { return strings.Contains(l, "user alice") }) {
		t.Errorf("after the removal: %q", f.running)
	}
}

// A router whose commit-confirm would reboot it is worth a warning.
func TestVyOSWarnsOfARebootOnRollback(t *testing.T) {
	_, ssh := netVyOS(t, "set system host-name r1")
	host := onSwitch(eosStep("conn3x_vyos_hostname", map[string]cty.Value{"name": cty.StringVal("r1")}, nil), ssh)
	resp := vyosHostnameKind.read(ctx, providers.ReadResourceRequest{PriorState: host})
	if resp.Diagnostics.HasErrors() || len(resp.Diagnostics) != 1 || !strings.Contains(resp.Diagnostics[0].Description().Summary, "reboot") {
		t.Errorf("diagnostics = %v", resp.Diagnostics)
	}
}
