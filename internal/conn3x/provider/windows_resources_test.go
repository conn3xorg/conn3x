// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func winSSH(t *testing.T, r resourceType, attrs map[string]cty.Value) cty.Value {
	t.Helper()
	cfg := objFor(r.schema(), nil).AsValueMap()
	conn := cfg["ssh"].AsValueMap()
	for k, v := range attrs {
		conn[k] = v
	}
	cfg["ssh"] = cty.ObjectVal(conn)
	cfg["path"] = cty.StringVal(`C:\ready`)
	return cty.ObjectVal(cfg)
}

func TestWindowsTypesRejectLinuxOnlySSHSettings(t *testing.T) {
	p := &Provider{}
	for _, name := range []string{"conn3x_windows_wait_for", "conn3x_windows_reboot", "conn3x_windows_powershell"} {
		r := resourceTypes[name]
		for attr, val := range map[string]cty.Value{"agent": cty.True, "become_password_file": cty.StringVal("/x")} {
			resp := p.ValidateResourceConfig(context.Background(), providers.ValidateResourceConfigRequest{TypeName: name, Config: winSSH(t, r, map[string]cty.Value{attr: val})})
			if !resp.Diagnostics.HasErrors() {
				t.Errorf("%s accepted ssh.%s", name, attr)
			}
		}
		resp := p.ValidateResourceConfig(context.Background(), providers.ValidateResourceConfigRequest{TypeName: name, Config: winSSH(t, r, map[string]cty.Value{"agent": cty.False, "become": cty.True})})
		if resp.Diagnostics.HasErrors() {
			t.Errorf("%s rejected agent = false, become = true: %v", name, resp.Diagnostics.Err())
		}
	}
	// A Linux type keeps them.
	r := resourceTypes["conn3x_wait_for"]
	resp := p.ValidateResourceConfig(context.Background(), providers.ValidateResourceConfigRequest{TypeName: "conn3x_wait_for", Config: winSSH(t, r, map[string]cty.Value{"agent": cty.True, "become_password_file": cty.StringVal("/x")})})
	for _, d := range resp.Diagnostics {
		if strings.Contains(d.Description().Summary, "Windows") {
			t.Errorf("a Linux step got a Windows error: %v", d.Description())
		}
	}
}

func TestWinRebootPlan(t *testing.T) {
	r := resourceTypes["conn3x_windows_reboot"]
	cfg := objFor(r.schema(), map[string]cty.Value{"only_if_pending": cty.True})
	created := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
	if created.GetAttr("boot_id").IsKnown() {
		t.Fatalf("planned = %#v", created)
	}
	vals := created.AsValueMap()
	vals["boot_id"], vals["pending"] = cty.StringVal("5"), cty.False
	clean := cty.ObjectVal(vals)
	if p := r.plan(providers.PlanResourceChangeRequest{PriorState: clean, ProposedNewState: clean, Config: clean}).PlannedState; !p.RawEquals(clean) {
		t.Errorf("nothing pending planned a change: %#v", p)
	}
	vals["pending"] = cty.True
	pending := cty.ObjectVal(vals)
	p := r.plan(providers.PlanResourceChangeRequest{PriorState: pending, ProposedNewState: pending, Config: pending})
	if p.PlannedState.GetAttr("boot_id").IsKnown() || len(p.RequiresReplace) != 0 {
		t.Errorf("a pending reboot must plan an update: %#v %v", p.PlannedState, p.RequiresReplace)
	}
	// Without only_if_pending, pending doesn't drive anything.
	vals["only_if_pending"] = cty.NullVal(cty.Bool)
	off := cty.ObjectVal(vals)
	if p := r.plan(providers.PlanResourceChangeRequest{PriorState: off, ProposedNewState: off, Config: off}).PlannedState; !p.GetAttr("boot_id").IsKnown() {
		t.Error("planned a reboot without only_if_pending")
	}
}

func TestWinPowershellPlan(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	r := resourceTypes["conn3x_windows_powershell"]
	wo := func(v string) cty.Value { return cty.MapVal(map[string]cty.Value{"pw": cty.StringVal(v)}) }
	cfg := objFor(r.schema(), map[string]cty.Value{"script": cty.StringVal("param($A) 1"), "args_wo": wo("s3cret")})
	resp := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg})
	if resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	planned := resp.PlannedState
	if !planned.GetAttr("args_wo").IsNull() || planned.GetAttr("args_hmac").IsNull() {
		t.Fatalf("args_wo %#v, args_hmac %#v", planned.GetAttr("args_wo"), planned.GetAttr("args_hmac"))
	}
	if planned.GetAttr("id").AsString() != "203.0.113.10:windows_powershell" {
		t.Errorf("id = %#v", planned.GetAttr("id"))
	}
	vals := planned.AsValueMap()
	vals["satisfied"], vals["stdout"], vals["stderr"], vals["revision"] = cty.True, cty.StringVal(""), cty.StringVal(""), cty.StringVal("r")
	prior := cty.ObjectVal(vals)

	proposed := func(secret string) (cty.Value, cty.Value) {
		c := cfg.AsValueMap()
		c["args_wo"] = wo(secret)
		p := prior.AsValueMap()
		return cty.ObjectVal(p), cty.ObjectVal(c)
	}
	state, config := proposed("s3cret")
	if p := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: state, Config: config}); !p.PlannedState.GetAttr("satisfied").IsKnown() {
		t.Error("the same secret planned a rerun")
	}
	state, config = proposed("changed")
	if p := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: state, Config: config}); p.PlannedState.GetAttr("satisfied").IsKnown() {
		t.Error("a new secret did not plan a rerun")
	}
}

func TestWinPowershellValidate(t *testing.T) {
	r := resourceTypes["conn3x_windows_powershell"]
	ok := map[string]cty.Value{"script": cty.StringVal("1"), "creates": cty.StringVal(`C:\x`), "timeout": cty.StringVal("1m")}
	if d := r.validate(objFor(r.schema(), ok)); d.HasErrors() {
		t.Error(d.Err())
	}
	both := cty.MapVal(map[string]cty.Value{"a": cty.StringVal("1")})
	for name, bad := range map[string]map[string]cty.Value{
		"empty":   {"script": cty.StringVal("")},
		"posix":   {"script": cty.StringVal("1"), "creates": cty.StringVal("/etc/x")},
		"timeout": {"script": cty.StringVal("1"), "timeout": cty.StringVal("soon")},
		"both":    {"script": cty.StringVal("1"), "args": both, "args_wo": both},
	} {
		if !r.validate(objFor(r.schema(), bad)).HasErrors() {
			t.Errorf("%s: accepted %v", name, bad)
		}
	}
}

// Windows steps stay off the POSIX path, the agent and sudo.
func TestWindowsResourcesDontUseTheShellRunner(t *testing.T) {
	b, err := os.ReadFile("windows_resources.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"h.Run(", "h.runner", "dialConnection(", "dialForApply(", "ssh.Quote"} {
		if strings.Contains(string(b), banned) {
			t.Errorf("windows_resources.go uses %s", banned)
		}
	}
}
