// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func winSvcList(vs ...string) cty.Value {
	var l []cty.Value
	for _, v := range vs {
		l = append(l, cty.StringVal(v))
	}
	return cty.ListVal(l)
}

// winSvcRule is the host's answer for an enabled inbound TCP rule.
func winSvcRule(action string, ports, addresses []any, profile int) map[string]any {
	return map[string]any{"exists": true, "display_name": "web", "direction": "Inbound", "action": action, "enabled": true, "profile": profile,
		"protocol": "TCP", "local_ports": ports, "remote_addresses": addresses}
}

func TestWinFirewallRuleLifecycle(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("apply_firewall_rule.ps1", nil)
	h.on("apply_firewall_rule_remove.ps1", nil)
	h.on("read_ssh_connection.ps1", "198.51.100.7 50000 10.0.0.4 22")
	want := winSvcRule("Allow", []any{"443", "8000-8100"}, []any{"10.0.0.0/8"}, 3)
	winSvcOnApplied(h, "read_firewall_rule.ps1", "apply_firewall_rule.ps1", map[string]any{"exists": false}, want)
	cfg := h.step("conn3x_windows_firewall_rule", map[string]cty.Value{
		"name": cty.StringVal("web"), "protocol": cty.StringVal("tcp"), "local_ports": winSvcList("8000-8100", "443"),
		"remote_addresses": winSvcList("10.0.0.0/8"), "profiles": winSvcList("domain", "private"), "description": cty.StringVal(""),
	})
	state := h.create("conn3x_windows_firewall_rule", cfg)
	if !winSynced(t, state) {
		t.Error("a created rule isn't in sync")
	}
	got := h.sent("apply_firewall_rule.ps1")
	if len(got) != 1 || got[0]["direction"] != "Inbound" || got[0]["action"] != "Allow" || got[0]["protocol"] != "TCP" || got[0]["display_name"] != nil || got[0]["enabled"] != true {
		t.Fatalf("apply sent %v", got)
	}
	if p, _ := got[0]["profiles"].([]any); len(p) != 2 || p[0] != "Domain" || p[1] != "Private" {
		t.Errorf("profiles sent %v", got[0]["profiles"])
	}

	// Ports and addresses compare as sets.
	h.on("read_firewall_rule.ps1", winSvcRule("Allow", []any{"8000-8100", "443", "443"}, []any{"10.0.0.0/8"}, 3))
	if r := h.read("conn3x_windows_firewall_rule", state); !winSynced(t, r.NewState) {
		t.Error("the same rule read as drift")
	}
	h.on("read_firewall_rule.ps1", winSvcRule("Allow", []any{"443"}, []any{"10.0.0.0/8"}, 3))
	if r := h.read("conn3x_windows_firewall_rule", state); winSynced(t, r.NewState) {
		t.Error("a missing port range read as in sync")
	}
	h.on("read_firewall_rule.ps1", "?")
	if r := h.read("conn3x_windows_firewall_rule", state); !r.Diagnostics.HasErrors() {
		t.Error("a malformed refresh reported no error")
	}

	// This rule doesn't carry Conn3x's connection, so it can go.
	h.on("read_firewall_rule.ps1", want)
	if r := h.destroy("conn3x_windows_firewall_rule", state); r.Diagnostics.HasErrors() {
		t.Fatal(r.Diagnostics.Err())
	}
	if got := h.sent("apply_firewall_rule_remove.ps1"); len(got) != 1 || got[0]["name"] != "web" {
		t.Errorf("remove sent %v", got)
	}
}

// The guard sees the connection as the host does: a rule that lets Conn3x
// in can't be deleted, or narrowed to leave it out.
func TestWinFirewallRuleKeepsConn3xIn(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("apply_firewall_rule.ps1", nil)
	h.on("apply_firewall_rule_remove.ps1", nil)
	h.on("read_ssh_connection.ps1", "198.51.100.7 50000 10.0.0.4 22")
	h.on("read_firewall_rule.ps1", winSvcRule("Allow", []any{"22"}, []any{}, 7))
	cfg := h.step("conn3x_windows_firewall_rule", map[string]cty.Value{"name": cty.StringVal("ssh"), "protocol": cty.StringVal("tcp"), "local_ports": winSvcList("22")})
	planned := h.plan("conn3x_windows_firewall_rule", cty.NullVal(cfg.Type()), cfg).PlannedState
	vals := planned.AsValueMap()
	vals["in_sync"] = cty.True
	state := cty.ObjectVal(vals)
	r := h.destroy("conn3x_windows_firewall_rule", state)
	if !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "deleting it could cut Conn3x off") {
		t.Errorf("delete: %v", r.Diagnostics.Err())
	}
	narrow := h.step("conn3x_windows_firewall_rule", map[string]cty.Value{"name": cty.StringVal("ssh"), "protocol": cty.StringVal("tcp"), "local_ports": winSvcList("22"), "remote_addresses": winSvcList("10.0.0.0/8")})
	r = h.update("conn3x_windows_firewall_rule", state, narrow)
	if !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "this change would stop it") {
		t.Errorf("narrowing: %v", r.Diagnostics.Err())
	}
	block := h.step("conn3x_windows_firewall_rule", map[string]cty.Value{"name": cty.StringVal("ssh"), "action": cty.StringVal("block"), "protocol": cty.StringVal("tcp"), "local_ports": winSvcList("22"), "remote_addresses": winSvcList("198.51.100.0/24")})
	r = h.update("conn3x_windows_firewall_rule", state, block)
	if !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "block rules beat allow rules") {
		t.Errorf("blocking: %v", r.Diagnostics.Err())
	}
	if a := h.applied(); len(a) != 0 {
		t.Errorf("refused changes ran %v", a)
	}

	// Without SSH_CONNECTION, nothing near the port changes.
	// The port is then the one the step connects to, which this rule takes in.
	h.on("read_ssh_connection.ps1", "")
	h.on("read_firewall_rule.ps1", winSvcRule("Allow", nil, nil, 7))
	r = h.update("conn3x_windows_firewall_rule", state, narrow)
	if !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "didn't report which address") {
		t.Errorf("unknown client: %v", r.Diagnostics.Err())
	}
}

func TestWinFirewallRuleHostErrors(t *testing.T) {
	h := newWinFakeHost(t)
	cfg := h.step("conn3x_windows_firewall_rule", map[string]cty.Value{"name": cty.StringVal("web"), "protocol": cty.StringVal("tcp"), "local_ports": winSvcList("443")})
	null := cty.NullVal(cfg.Type())
	h.on("read_firewall_rule.ps1", map[string]any{"exists": false})
	h.on("read_ssh_connection.ps1", "198.51.100.7 50000 10.0.0.4 22")
	h.fail("apply_firewall_rule.ps1", "a group policy owns this rule")
	if r := h.update("conn3x_windows_firewall_rule", null, cfg); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "rule web: a group policy owns this rule") {
		t.Errorf("a host error: %v", r.Diagnostics.Err())
	}
	// A set the host doesn't keep is an error.
	h.on("apply_firewall_rule.ps1", nil)
	if r := h.update("conn3x_windows_firewall_rule", null, cfg); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "a group policy may own it") {
		t.Errorf("a set that didn't take: %v", r.Diagnostics.Err())
	}
	h.fail("read_ssh_connection.ps1", "no session")
	if r := h.update("conn3x_windows_firewall_rule", null, cfg); !r.Diagnostics.HasErrors() || len(h.sent("apply_firewall_rule.ps1")) != 2 {
		t.Errorf("an unread connection: %v", r.Diagnostics.Err())
	}
	h.fail("read_firewall_rule.ps1", "no firewall service")
	if r := h.update("conn3x_windows_firewall_rule", null, cfg); !r.Diagnostics.HasErrors() {
		t.Error("an unread rule applied")
	}

	// A block from everywhere on the port Conn3x connects to stops at apply,
	// before the host.
	port := h.conn.GetAttr("port").AsBigFloat().String()
	lock := h.step("conn3x_windows_firewall_rule", map[string]cty.Value{"name": cty.StringVal("x"), "action": cty.StringVal("block"), "protocol": cty.StringVal("tcp"), "local_ports": winSvcList(port)})
	if d := resourceTypes["conn3x_windows_firewall_rule"].validate(lock); !d.HasErrors() {
		t.Error("validate accepted a lockout")
	}
	n := len(h.sent("read_firewall_rule.ps1"))
	if r := h.update("conn3x_windows_firewall_rule", null, lock); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "cuts Conn3x off") || len(h.sent("read_firewall_rule.ps1")) != n {
		t.Errorf("a lockout: %v", r.Diagnostics.Err())
	}
	// A name with nothing else would let everything in.
	if d := resourceTypes["conn3x_windows_firewall_rule"].validate(h.step("conn3x_windows_firewall_rule", map[string]cty.Value{"name": cty.StringVal("x")})); !d.HasErrors() {
		t.Error("validate accepted an allow-everything rule")
	}
}
