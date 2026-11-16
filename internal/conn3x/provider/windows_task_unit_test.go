// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// winSysTask is a nightly task running job.exe, with extra attributes set.
func winSysTask(h *winFakeHost, extra map[string]cty.Value) cty.Value {
	daily := cty.ObjectVal(map[string]cty.Value{"type": cty.StringVal("daily"), "at": cty.StringVal("2026-01-01T03:00:00"), "days_interval": cty.NullVal(cty.Number)})
	attrs := map[string]cty.Value{
		"name": cty.StringVal("Nightly"), "path": cty.StringVal(`\Conn3x\`), "execute": cty.StringVal(`C:\Tools\job.exe`),
		"user": cty.StringVal("SYSTEM"), "trigger": cty.ListVal([]cty.Value{daily}),
	}
	for k, v := range extra {
		attrs[k] = v
	}
	return h.step("conn3x_windows_scheduled_task", attrs)
}

// winSysTaskOnHost is the task as read_task.ps1 reports it.
func winSysTaskOnHost(sid, logon string) map[string]any {
	return map[string]any{
		"exists":   true,
		"actions":  []map[string]any{{"execute": `c:\tools\job.exe`}},
		"triggers": []map[string]any{{"kind": "MSFT_TaskDailyTrigger", "start": "2026-01-01T03:00:00+00:00", "days": 1, "enabled": true}},
		"user_sid": sid, "want_sid": sid, "logon": logon, "run_level": "Limited", "enabled": true,
	}
}

func TestWinTaskLifecycle(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("apply_task.ps1", nil)
	winSysSeq(h, "read_task.ps1", map[string]any{"exists": false}, winSysTaskOnHost("S-1-5-18", "ServiceAccount"))
	cfg := winSysTask(h, nil)
	state := h.create("conn3x_windows_scheduled_task", cfg)
	if !winSynced(t, state) || state.GetAttr("on_remove").AsString() != "delete" {
		t.Fatalf("state %#v", state)
	}
	got := h.sent("apply_task.ps1")
	if len(got) != 1 || got[0]["path"] != `\Conn3x\` || got[0]["name"] != "Nightly" || got[0]["execute"] != `C:\Tools\job.exe` || got[0]["user"] != "SYSTEM" ||
		got[0]["has_password"] != false || got[0]["enabled"] != true || got[0]["highest"] != false || got[0]["password"] != nil ||
		fmt.Sprint(got[0]["triggers"]) != "[map[at:2026-01-01T03:00:00 days:1 type:daily]]" {
		t.Fatalf("apply sent %v", got)
	}
	if r := h.sent("read_task.ps1"); r[0]["path"] != `\Conn3x\` || r[0]["name"] != "Nightly" || r[0]["user"] != "SYSTEM" {
		t.Errorf("read sent %v", r)
	}
	if r := h.read("conn3x_windows_scheduled_task", state); !winSynced(t, r.NewState) {
		t.Error("a matching task read as out of sync")
	}
	// Already registered as asked: nothing changes.
	h.create("conn3x_windows_scheduled_task", cfg)
	if n := len(h.sent("apply_task.ps1")); n != 1 {
		t.Errorf("a matching task was registered %d times", n)
	}
	drift := winSysTaskOnHost("S-1-5-18", "ServiceAccount")
	drift["run_level"] = "Highest"
	h.on("read_task.ps1", drift)
	if r := h.read("conn3x_windows_scheduled_task", state); winSynced(t, r.NewState) {
		t.Error("a task running elevated read as in sync")
	}
	h.on("read_task.ps1", "x")
	if r := h.read("conn3x_windows_scheduled_task", state); !r.Diagnostics.HasErrors() {
		t.Error("a malformed answer read without error")
	}

	// on_remove defaults to delete for a task.
	h.on("apply_task_remove.ps1", nil)
	if r := h.destroy("conn3x_windows_scheduled_task", state); r.Diagnostics.HasErrors() {
		t.Fatal(r.Diagnostics.Err())
	}
	if got := h.sent("apply_task_remove.ps1"); len(got) != 1 || got[0]["path"] != `\Conn3x\` || got[0]["name"] != "Nightly" {
		t.Errorf("remove sent %v", got)
	}
	h.fail("apply_task_remove.ps1", "task is running")
	winSysErr(t, h.destroy("conn3x_windows_scheduled_task", state), "windows_scheduled_task: task is running")
	vals := state.AsValueMap()
	vals["on_remove"] = cty.StringVal("forget")
	if r := h.destroy("conn3x_windows_scheduled_task", cty.ObjectVal(vals)); r.Diagnostics.HasErrors() || len(h.sent("apply_task_remove.ps1")) != 2 {
		t.Errorf("forget: %v", r.Diagnostics.Err())
	}
}

// A password can't be compared on the host, so a new one always registers
// the task, and the same one never does.
func TestWinTaskPassword(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	h := newWinFakeHost(t)
	h.on("apply_task.ps1", nil)
	h.on("read_task.ps1", winSysTaskOnHost("S-1-5-21-1-1105", "Password"))
	cfg := winSysTask(h, map[string]cty.Value{"user": cty.StringVal(`LAB\svc`), "password_wo": cty.StringVal("s3ntinel-pw")})
	state := h.create("conn3x_windows_scheduled_task", cfg)
	if !known(state.GetAttr("password_hmac")) || strings.Contains(fmt.Sprintf("%#v", state), "s3ntinel") {
		t.Fatalf("state %#v", state)
	}
	if got := h.sent("apply_task.ps1"); len(got) != 1 || got[0]["password"] != "s3ntinel-pw" || got[0]["has_password"] != true {
		t.Fatalf("apply sent %v", got)
	}
	if r := h.update("conn3x_windows_scheduled_task", state, cfg); r.Diagnostics.HasErrors() || len(h.sent("apply_task.ps1")) != 1 {
		t.Errorf("the same password registered again: %v", r.Diagnostics.Err())
	}
	other := winSysTask(h, map[string]cty.Value{"user": cty.StringVal(`LAB\svc`), "password_wo": cty.StringVal("n3w-pw")})
	if r := h.update("conn3x_windows_scheduled_task", state, other); r.Diagnostics.HasErrors() || len(h.sent("apply_task.ps1")) != 2 {
		t.Errorf("a new password didn't register: %v", r.Diagnostics.Err())
	}
	// The refresh asks for a password logon.
	if r := h.read("conn3x_windows_scheduled_task", state); !winSynced(t, r.NewState) {
		t.Error("a password task read as out of sync")
	}
	h.fail("apply_task.ps1", "logon failure for n3w-pw")
	r := h.update("conn3x_windows_scheduled_task", state, other)
	if winSysErr(t, r, `task \Conn3x\Nightly:`); strings.Contains(r.Diagnostics.Err().Error(), "n3w-pw") {
		t.Errorf("the password reached the error: %v", r.Diagnostics.Err())
	}
}

func TestWinTaskApplyFailures(t *testing.T) {
	h := newWinFakeHost(t)
	cfg := winSysTask(h, nil)
	h.on("apply_task.ps1", nil)
	h.on("read_task.ps1", map[string]any{"exists": false})
	winSysErr(t, winSysApply(h, "conn3x_windows_scheduled_task", cfg), "doesn't match what was registered")
	h.fail("read_task.ps1", "Task Scheduler is stopped")
	winSysErr(t, winSysApply(h, "conn3x_windows_scheduled_task", cfg), "windows_scheduled_task: Task Scheduler is stopped")

	// The plan can't make a task the module would refuse.
	planned := h.plan("conn3x_windows_scheduled_task", cty.NullVal(cfg.Type()), cfg).PlannedState
	vals := planned.AsValueMap()
	vals["execute"] = cty.StringVal("job.exe")
	r := resourceTypes["conn3x_windows_scheduled_task"].apply(context.Background(), providers.ApplyResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), PlannedState: cty.ObjectVal(vals), Config: cfg})
	winSysErr(t, r, "windows_scheduled_task:")
	if n := len(h.applied()); n != 1 {
		t.Errorf("ran %v", h.applied())
	}
}
