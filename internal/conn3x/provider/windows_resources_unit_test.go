// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"sync/atomic"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// withBecome is the host's ssh block with become set.
func (h *winFakeHost) withBecome() cty.Value {
	conn := h.conn.AsValueMap()
	conn["become"] = cty.True
	return cty.ObjectVal(conn)
}

// become checks the login is elevated once per connection, and refuses one
// that isn't, since there is no user to switch to.
func TestWinHostBecome(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("read_elevated.ps1", true)
	for range 2 {
		if _, err := winHost(ctx, h.withBecome()); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(h.sent("read_elevated.ps1")); n != 1 {
		t.Errorf("checked elevation %d times", n)
	}

	low := newWinFakeHost(t)
	low.on("read_elevated.ps1", false)
	if _, err := winHost(ctx, low.withBecome()); err == nil || !strings.Contains(err.Error(), "isn't elevated") {
		t.Errorf("not elevated: %v", err)
	}
	low = newWinFakeHost(t)
	low.on("read_elevated.ps1", "yes")
	if _, err := winHost(ctx, low.withBecome()); err == nil || !strings.Contains(err.Error(), "not a boolean") {
		t.Errorf("a malformed answer: %v", err)
	}
	// A step reports a host it can't reach against ssh.
	conn := h.conn.AsValueMap()
	conn["port"], conn["timeout"] = cty.NumberIntVal(1), cty.StringVal("1s")
	state := h.step("conn3x_windows_environment", map[string]cty.Value{"name": cty.StringVal("A"), "value": cty.StringVal("1")})
	vals := state.AsValueMap()
	vals["ssh"] = cty.ObjectVal(conn)
	if r := h.read("conn3x_windows_environment", cty.ObjectVal(vals)); !r.Diagnostics.HasErrors() {
		t.Error("an unreachable host read without error")
	}
}

func TestWinWaitForReadAndApply(t *testing.T) {
	h := newWinFakeHost(t)
	const typ = "conn3x_windows_wait_for"
	h.on("read_wait.ps1", true)
	cfg := h.step(typ, map[string]cty.Value{"port": cty.NumberIntVal(8080), "timeout": cty.StringVal("1ns")})
	state := h.create(typ, cfg)
	if !winSynced(t, state) {
		t.Error("ready, but not in sync")
	}
	if got := h.sent("read_wait.ps1"); len(got) != 1 || got[0]["port"] != float64(8080) || got[0]["path"] != "" {
		t.Errorf("wait sent %v", got)
	}
	h.on("read_wait.ps1", false)
	if r := h.read(typ, state); r.Diagnostics.HasErrors() || winSynced(t, r.NewState) {
		t.Errorf("stopped listening: %v", r.Diagnostics.Err())
	}
	// Only how Conn3x reaches the host changed: nothing to wait for.
	n := len(h.sent("read_wait.ps1"))
	if r := resourceTypes[typ].apply(ctx, providers.ApplyResourceChangeRequest{PriorState: state, PlannedState: state, Config: cfg}); r.Diagnostics.HasErrors() || len(h.sent("read_wait.ps1")) != n {
		t.Errorf("an in-sync apply waited: %v", r.Diagnostics.Err())
	}
	// Never ready: it gives up at the timeout, saying what it waited for. A
	// timeout under the poll interval gives up after the first check.
	r := h.update(typ, cty.NullVal(cfg.Type()), cfg)
	if !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "timed out after 0s waiting for") {
		t.Errorf("never ready: %v", r.Diagnostics.Err())
	}
	h.fail("read_wait.ps1", "Get-Service failed")
	if r := h.update(typ, cty.NullVal(cfg.Type()), cfg); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "Get-Service failed") {
		t.Errorf("the last error: %v", r.Diagnostics.Err())
	}
	if r := h.read(typ, state); !r.Diagnostics.HasErrors() {
		t.Error("a failed check read without error")
	}
	// Two targets, or none, are refused at validate, refresh and apply.
	bad := h.step(typ, map[string]cty.Value{"port": cty.NumberIntVal(1), "service": cty.StringVal("W3SVC")})
	if !resourceTypes[typ].validate(bad).HasErrors() {
		t.Error("validate accepted two targets")
	}
	if r := h.read(typ, bad); !r.Diagnostics.HasErrors() {
		t.Error("refresh accepted two targets")
	}
	if r := h.update(typ, cty.NullVal(bad.Type()), bad); !r.Diagnostics.HasErrors() {
		t.Error("apply accepted two targets")
	}
}

func TestWinRebootReadAndApply(t *testing.T) {
	h := newWinFakeHost(t)
	const typ = "conn3x_windows_reboot"
	var boots atomic.Int32
	h.onFunc("read_boot_id.ps1", func(map[string]any) (any, string) { return []string{"boot-a", "boot-b"}[boots.Load()], "" })
	h.onFunc("apply_reboot.ps1", func(map[string]any) (any, string) { boots.Store(1); return nil, "" })
	h.on("read_pending_reboot.ps1", false)
	cfg := h.step(typ, map[string]cty.Value{"only_if_pending": cty.True})

	// Nothing pending: no reboot, and the boot it found.
	state := h.create(typ, cfg)
	if state.GetAttr("boot_id").AsString() != "boot-a" || state.GetAttr("pending").True() || len(h.applied()) != 0 {
		t.Fatalf("state %#v, applied %v", state, h.applied())
	}
	h.on("read_pending_reboot.ps1", true)
	if r := h.read(typ, state); r.Diagnostics.HasErrors() || !r.NewState.GetAttr("pending").True() {
		t.Errorf("pending: %v %#v", r.Diagnostics.Err(), r.NewState.GetAttr("pending"))
	}
	// Pending: it reboots and waits for a new boot. The fake host comes
	// back at once, so this costs one poll.
	h.onFunc("read_pending_reboot.ps1", func(map[string]any) (any, string) { return boots.Load() == 0, "" })
	state = h.create(typ, cfg)
	if state.GetAttr("boot_id").AsString() != "boot-b" || state.GetAttr("pending").True() {
		t.Errorf("after the reboot: %#v", state)
	}
	if got := h.applied(); len(got) != 1 || got[0] != "apply_reboot.ps1" {
		t.Errorf("applied %v", got)
	}

	// Without only_if_pending, refresh doesn't ask the host.
	plain := h.step(typ, nil)
	n := len(h.sent("read_pending_reboot.ps1"))
	if r := h.read(typ, plain); r.Diagnostics.HasErrors() || len(h.sent("read_pending_reboot.ps1")) != n {
		t.Errorf("a plain reboot refreshed: %v", r.Diagnostics.Err())
	}
	h.fail("read_pending_reboot.ps1", "denied")
	if r := h.read(typ, state); !r.Diagnostics.HasErrors() {
		t.Error("a failed check read without error")
	}
	if r := h.update(typ, cty.NullVal(cfg.Type()), cfg); !r.Diagnostics.HasErrors() {
		t.Error("a failed pending check applied")
	}
	h.on("read_boot_id.ps1", "")
	if r := h.update(typ, cty.NullVal(cfg.Type()), cfg); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "boot id") {
		t.Errorf("an empty boot id: %v", r.Diagnostics.Err())
	}
	h.on("read_boot_id.ps1", "boot-c")
	h.fail("apply_reboot.ps1", "shutdown.exe failed")
	if r := h.update(typ, cty.NullVal(plain.Type()), plain); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "scheduling a reboot: shutdown.exe failed") {
		t.Errorf("a failed reboot: %v", r.Diagnostics.Err())
	}
	bad := h.step(typ, map[string]cty.Value{"timeout": cty.StringVal("soon")})
	if r := h.update(typ, cty.NullVal(bad.Type()), bad); !r.Diagnostics.HasErrors() {
		t.Error("a bad timeout applied")
	}
}

func TestWinPowershellApply(t *testing.T) {
	h := newWinFakeHost(t)
	const typ, script = "conn3x_windows_powershell", "param($A) Install-Thing $A.name"
	h.on(script, winRaw{"text": "installed\n", "rc": 0})
	cfg := h.step(typ, map[string]cty.Value{"script": cty.StringVal(script), "args": cty.MapVal(map[string]cty.Value{"name": cty.StringVal("thing")})})
	state := h.create(typ, cfg)
	if state.GetAttr("stdout").AsString() != "installed\n" || !state.GetAttr("satisfied").True() {
		t.Errorf("state %#v", state)
	}
	if got := h.sent(script); len(got) != 1 || got[0]["name"] != "thing" {
		t.Errorf("script got %v", got)
	}
	// No guards: refresh has nothing to ask.
	if r := h.read(typ, state); r.Diagnostics.HasErrors() || len(h.sent(script)) != 1 {
		t.Errorf("refresh ran something: %v", r.Diagnostics.Err())
	}
	// A plan that found nothing to rerun runs nothing.
	if r := resourceTypes[typ].apply(ctx, providers.ApplyResourceChangeRequest{PriorState: state, PlannedState: state, Config: cfg}); r.Diagnostics.HasErrors() || len(h.sent(script)) != 1 {
		t.Errorf("reran: %v", r.Diagnostics.Err())
	}

	h.on(script, winRaw{"text": "", "rc": 3})
	if r := h.update(typ, cty.NullVal(cfg.Type()), cfg); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "exited with 3") {
		t.Errorf("a native failure: %v", r.Diagnostics.Err())
	}
	h.fail(script, "Install-Thing: not found")
	if r := h.update(typ, cty.NullVal(cfg.Type()), cfg); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "Install-Thing: not found") {
		t.Errorf("a throw: %v", r.Diagnostics.Err())
	}
	bad := h.step(typ, map[string]cty.Value{"script": cty.StringVal(script), "timeout": cty.StringVal("soon")})
	if r := h.update(typ, cty.NullVal(bad.Type()), bad); !r.Diagnostics.HasErrors() {
		t.Error("a bad timeout applied")
	}
}

// creates and unless decide whether the script runs, and must hold after.
func TestWinPowershellGuards(t *testing.T) {
	h := newWinFakeHost(t)
	const typ, script = "conn3x_windows_powershell", "param($A) New-Item C:\\done"
	h.on(script, winRaw{"text": "ok", "rc": 0})
	var made atomic.Bool
	h.onFunc("read_guards.ps1", func(map[string]any) (any, string) { return made.Load(), "" })
	h.onFunc(script, func(map[string]any) (any, string) { made.Store(true); return winRaw{"text": "ok", "rc": 0}, "" })
	cfg := h.step(typ, map[string]cty.Value{"script": cty.StringVal(script), "creates": cty.StringVal(`C:\done`)})
	h.create(typ, cfg)
	if got := h.sent("read_guards.ps1"); len(got) != 2 || got[0]["creates"] != `C:\done` {
		t.Errorf("guards sent %v", got)
	}
	// Already done: the script doesn't run again.
	state := h.create(typ, cfg)
	if n := len(h.sent(script)); n != 1 {
		t.Errorf("ran %d times", n)
	}
	if r := h.read(typ, state); r.Diagnostics.HasErrors() || !r.NewState.GetAttr("satisfied").True() {
		t.Errorf("refresh: %v", r.Diagnostics.Err())
	}
	made.Store(false)
	if r := h.read(typ, state); r.NewState.GetAttr("satisfied").True() {
		t.Error("a missing path read as satisfied")
	}
	// A script that doesn't do what its guard says fails rather than rerun forever.
	h.on(script, winRaw{"text": "", "rc": 0})
	if r := h.update(typ, cty.NullVal(cfg.Type()), cfg); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "guards still don't hold") {
		t.Errorf("guard after: %v", r.Diagnostics.Err())
	}
	h.fail("read_guards.ps1", "denied")
	if r := h.read(typ, state); !r.Diagnostics.HasErrors() {
		t.Error("a failed guard read without error")
	}
	if r := h.update(typ, cty.NullVal(cfg.Type()), cfg); !r.Diagnostics.HasErrors() {
		t.Error("a failed guard applied")
	}

	// unless runs as the user wrote it, with args; a false last output means run.
	const check = "param($A) Test-Thing $A.name"
	h.on(check, winRaw{"value": false, "text": "False", "rc": 0})
	h.on(script, winRaw{"text": "", "rc": 0})
	un := h.step(typ, map[string]cty.Value{"script": cty.StringVal(script), "unless": cty.StringVal(check), "args": cty.MapVal(map[string]cty.Value{"name": cty.StringVal("x")})})
	if r := h.update(typ, cty.NullVal(un.Type()), un); !r.Diagnostics.HasErrors() {
		t.Error("unless still false after the run, but applied")
	}
	if got := h.sent(check); len(got) == 0 || got[0]["name"] != "x" {
		t.Errorf("unless got %v", got)
	}
	// A check that throws doesn't hold.
	h.fail(check, "no such thing")
	st := un.AsValueMap()
	st["satisfied"] = cty.True
	if r := h.read(typ, cty.ObjectVal(st)); r.Diagnostics.HasErrors() || r.NewState.GetAttr("satisfied").True() {
		t.Errorf("a throwing check: %v", r.Diagnostics.Err())
	}
	h.on(check, winRaw{"text": "", "rc": 0})
	if r := h.read(typ, cty.ObjectVal(st)); !r.NewState.GetAttr("satisfied").True() {
		t.Error("a passing check read as unsatisfied")
	}
}

// args_wo reaches the script but never state, output or errors.
func TestWinPowershellSecretArgs(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	h := newWinFakeHost(t)
	const typ, script, secret = "conn3x_windows_powershell", "param($A) Set-Pw $A.pw", "hunter2hunter2"
	h.on(script, winRaw{"text": "set " + secret, "rc": 0})
	cfg := h.step(typ, map[string]cty.Value{"script": cty.StringVal(script), "args_wo": cty.MapVal(map[string]cty.Value{"pw": cty.StringVal(secret)})})
	state := h.create(typ, cfg)
	if got := h.sent(script); len(got) != 1 || got[0]["pw"] != secret {
		t.Errorf("script got %v", got)
	}
	key, _ := hmacKey(false)
	mac, _ := argsHMAC(key, cfg.GetAttr("args_wo"))
	if !state.GetAttr("args_wo").IsNull() || state.GetAttr("args_hmac").AsString() != mac || strings.Contains(state.GetAttr("stdout").AsString(), secret) {
		t.Errorf("state %#v", state)
	}
	h.fail(script, "bad password "+secret)
	if r := h.update(typ, cty.NullVal(cfg.Type()), cfg); !r.Diagnostics.HasErrors() || strings.Contains(r.Diagnostics.Err().Error(), secret) {
		t.Errorf("error %v", r.Diagnostics.Err())
	}
	// A plan over state hashed with another key is refused.
	t.Setenv(hmacKeyEnv, strings.Repeat("j", 32))
	if r := resourceTypes[typ].plan(providers.PlanResourceChangeRequest{PriorState: state, ProposedNewState: state, Config: cfg}); !r.Diagnostics.HasErrors() {
		t.Error("a different key planned")
	}
}
