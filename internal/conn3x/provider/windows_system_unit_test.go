// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/providers"
)

// winSysSeq answers successive runs of script with values, then keeps
// answering with the last: what the host says before a change, then after.
func winSysSeq(h *winFakeHost, script string, values ...any) {
	var mu sync.Mutex
	n := 0
	h.onFunc(script, func(map[string]any) (any, string) {
		mu.Lock()
		defer mu.Unlock()
		v := values[min(n, len(values)-1)]
		n++
		return v, ""
	})
}

// winSysApply plans cfg from nothing and applies it, returning the response
// rather than failing, for applies that are meant to fail.
func winSysApply(h *winFakeHost, typeName string, cfg cty.Value) providers.ApplyResourceChangeResponse {
	h.t.Helper()
	return h.update(typeName, cty.NullVal(cfg.Type()), cfg)
}

func winSysErr(t *testing.T, r providers.ApplyResourceChangeResponse, want string) {
	t.Helper()
	if !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), want) {
		t.Errorf("want an error with %q, got %v", want, r.Diagnostics.Err())
	}
}

func TestWinRegistryLifecycle(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("apply_registry.ps1", nil)
	h.on("read_registry.ps1", map[string]any{"exists": true, "kind": "DWord", "data": "1"})
	cfg := h.step("conn3x_windows_registry_value", map[string]cty.Value{
		"key": cty.StringVal(`HKLM\SOFTWARE\App`), "name": cty.StringVal("Level"), "type": cty.StringVal("dword"), "data": cty.StringVal("01"), "on_remove": cty.StringVal("delete"),
	})
	state := h.create("conn3x_windows_registry_value", cfg)
	if !winSynced(t, state) {
		t.Error("a written value isn't in sync")
	}
	got := h.sent("apply_registry.ps1")
	if len(got) != 1 || got[0]["key"] != `SOFTWARE\App` || got[0]["name"] != "Level" || got[0]["kind"] != "DWord" || got[0]["data"] != "1" {
		t.Fatalf("apply sent %v", got)
	}
	if r := h.sent("read_registry.ps1"); r[0]["hash_only"] != false {
		t.Errorf("a plain value was read hash only: %v", r)
	}

	if r := h.read("conn3x_windows_registry_value", state); r.Diagnostics.HasErrors() || !winSynced(t, r.NewState) {
		t.Errorf("unchanged value: %v", r.Diagnostics.Err())
	}
	h.on("read_registry.ps1", map[string]any{"exists": true, "kind": "DWord", "data": "2"})
	if r := h.read("conn3x_windows_registry_value", state); winSynced(t, r.NewState) {
		t.Error("changed data read as in sync")
	}
	h.on("read_registry.ps1", map[string]any{"exists": true, "kind": "String", "data": "1"})
	if r := h.read("conn3x_windows_registry_value", state); winSynced(t, r.NewState) {
		t.Error("another type read as in sync")
	}
	h.on("read_registry.ps1", []int{1})
	if r := h.read("conn3x_windows_registry_value", state); !r.Diagnostics.HasErrors() {
		t.Error("a malformed answer read without error")
	}

	h.on("apply_registry_remove.ps1", nil)
	if r := h.destroy("conn3x_windows_registry_value", state); r.Diagnostics.HasErrors() {
		t.Fatal(r.Diagnostics.Err())
	}
	if got := h.sent("apply_registry_remove.ps1"); len(got) != 1 || got[0]["key"] != `SOFTWARE\App` || got[0]["name"] != "Level" {
		t.Errorf("remove sent %v", got)
	}
	h.fail("apply_registry_remove.ps1", "key is locked")
	winSysErr(t, h.destroy("conn3x_windows_registry_value", state), "windows_registry_value: key is locked")
}

// A write that something else undoes at once is an error, and a host's error
// never quotes the data back.
func TestWinRegistryApplyFailures(t *testing.T) {
	h := newWinFakeHost(t)
	cfg := h.step("conn3x_windows_registry_value", map[string]cty.Value{
		"key": cty.StringVal(`HKLM\SOFTWARE\App`), "name": cty.StringVal("Token"), "type": cty.StringVal("string"), "data": cty.StringVal("s3ntinel"),
	})
	h.on("apply_registry.ps1", nil)
	h.on("read_registry.ps1", map[string]any{"exists": true, "kind": "String", "data": "other"})
	winSysErr(t, winSysApply(h, "conn3x_windows_registry_value", cfg), "doesn't match what was written")

	h.fail("read_registry.ps1", "read refused")
	winSysErr(t, winSysApply(h, "conn3x_windows_registry_value", cfg), "read refused")

	h.fail("apply_registry.ps1", "cannot write s3ntinel to the key")
	r := winSysApply(h, "conn3x_windows_registry_value", cfg)
	winSysErr(t, r, "windows_registry_value:")
	if strings.Contains(r.Diagnostics.Err().Error(), "s3ntinel") {
		t.Errorf("the data reached the error: %v", r.Diagnostics.Err())
	}

	// on_remove defaults to forget, which leaves the host alone.
	h.on("apply_registry.ps1", nil)
	h.on("read_registry.ps1", map[string]any{"exists": true, "kind": "String", "data": "s3ntinel"})
	state := h.create("conn3x_windows_registry_value", cfg)
	n := len(h.applied())
	if r := h.destroy("conn3x_windows_registry_value", state); r.Diagnostics.HasErrors() || len(h.applied()) != n {
		t.Errorf("forget ran %v: %v", h.applied()[n:], r.Diagnostics.Err())
	}
}

// A secret is written once, read back by its hash only, and only its HMAC
// reaches state.
func TestWinRegistrySecret(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	h := newWinFakeHost(t)
	h.on("apply_registry.ps1", nil)
	h.on("read_registry.ps1", map[string]any{"exists": true, "kind": "String", "sha256": digest("hunter22")})
	cfg := h.step("conn3x_windows_registry_value", map[string]cty.Value{
		"key": cty.StringVal(`HKLM\SOFTWARE\App`), "name": cty.StringVal("Secret"), "type": cty.StringVal("string"), "data_wo": cty.StringVal("hunter22"),
	})
	state := h.create("conn3x_windows_registry_value", cfg)
	if strings.Contains(fmt.Sprintf("%#v", state), "hunter22") || !known(state.GetAttr("data_hmac")) || !state.GetAttr("data").IsNull() {
		t.Fatalf("state %#v", state)
	}
	if got := h.sent("apply_registry.ps1"); len(got) != 1 || got[0]["data"] != "hunter22" {
		t.Errorf("apply sent %v", got)
	}
	for _, r := range h.sent("read_registry.ps1") {
		if r["hash_only"] != true {
			t.Errorf("a secret was read whole: %v", r)
		}
	}
	if r := h.read("conn3x_windows_registry_value", state); r.Diagnostics.HasErrors() || !winSynced(t, r.NewState) {
		t.Errorf("unchanged secret: %v", r.Diagnostics.Err())
	}
	h.on("read_registry.ps1", map[string]any{"exists": true, "kind": "String", "sha256": digest("changed")})
	if r := h.read("conn3x_windows_registry_value", state); winSynced(t, r.NewState) {
		t.Error("a changed secret read as in sync")
	}
	winSysErr(t, winSysApply(h, "conn3x_windows_registry_value", cfg), "doesn't match what was written")

	// Under another key, the stored HMAC can't be checked.
	t.Setenv(hmacKeyEnv, strings.Repeat("o", 32))
	if r := h.read("conn3x_windows_registry_value", state); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "hashed with key") {
		t.Errorf("refresh under another key: %v", r.Diagnostics.Err())
	}
}

func TestWinServiceLifecycle(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("apply_service.ps1", nil)
	winSysSeq(h, "read_service.ps1",
		map[string]any{"exists": true, "start": "Manual", "status": "Stopped"},
		map[string]any{"exists": true, "start": "Automatic", "delayed": true, "status": "Running"})
	cfg := h.step("conn3x_windows_service", map[string]cty.Value{"name": cty.StringVal("W3SVC"), "start_mode": cty.StringVal("delayed"), "state": cty.StringVal("running")})
	state := h.create("conn3x_windows_service", cfg)
	if !winSynced(t, state) {
		t.Error("a changed service isn't in sync")
	}
	if got := h.sent("apply_service.ps1"); len(got) != 1 || got[0]["name"] != "W3SVC" || got[0]["start_mode"] != "delayed" || got[0]["state"] != "running" {
		t.Fatalf("apply sent %v", got)
	}
	if r := h.read("conn3x_windows_service", state); !winSynced(t, r.NewState) {
		t.Error("a matching service read as out of sync")
	}
	// Already as asked: nothing changes.
	h.create("conn3x_windows_service", cfg)
	if n := len(h.sent("apply_service.ps1")); n != 1 {
		t.Errorf("a matching service was changed %d times", n)
	}
	h.on("read_service.ps1", map[string]any{"exists": true, "start": "Automatic", "status": "Running"})
	if r := h.read("conn3x_windows_service", state); winSynced(t, r.NewState) {
		t.Error("auto read as delayed")
	}
	h.on("read_service.ps1", "nope")
	if r := h.read("conn3x_windows_service", state); !r.Diagnostics.HasErrors() {
		t.Error("a malformed answer read without error")
	}
	// Removing the step leaves the service as it is.
	if r := h.destroy("conn3x_windows_service", state); r.Diagnostics.HasErrors() || len(h.applied()) != 1 {
		t.Errorf("remove ran %v: %v", h.applied(), r.Diagnostics.Err())
	}
}

func TestWinServiceApplyFailures(t *testing.T) {
	h := newWinFakeHost(t)
	cfg := h.step("conn3x_windows_service", map[string]cty.Value{"name": cty.StringVal("Spooler"), "state": cty.StringVal("running")})
	h.on("read_service.ps1", map[string]any{"exists": false})
	winSysErr(t, winSysApply(h, "conn3x_windows_service", cfg), "no service named Spooler")

	h.on("read_service.ps1", map[string]any{"exists": true, "start": "Manual", "status": "Stopped"})
	h.fail("apply_service.ps1", "dependency failed")
	winSysErr(t, winSysApply(h, "conn3x_windows_service", cfg), "changing Spooler: dependency failed")

	// It started, then stopped before the check.
	h.on("apply_service.ps1", nil)
	winSysErr(t, winSysApply(h, "conn3x_windows_service", cfg), "may have stopped again")

	h.fail("read_service.ps1", "WMI is broken")
	winSysErr(t, winSysApply(h, "conn3x_windows_service", cfg), "WMI is broken")
	planned := h.plan("conn3x_windows_service", cty.NullVal(cfg.Type()), cfg).PlannedState
	vals := planned.AsValueMap()
	vals["state"] = cty.StringVal("paused")
	r := resourceTypes["conn3x_windows_service"].apply(context.Background(), providers.ApplyResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), PlannedState: cty.ObjectVal(vals), Config: cfg})
	winSysErr(t, r, `state "paused"`)
}

func TestWinFeatureLifecycle(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("apply_feature.ps1", map[string]any{"restart": true})
	winSysSeq(h, "read_feature.ps1",
		map[string]any{"exists": true, "state": "Available"},
		map[string]any{"exists": true, "state": "Installed", "installed": true})
	cfg := h.step("conn3x_windows_feature", map[string]cty.Value{"name": cty.StringVal("Web-Server"), "include_management_tools": cty.True})
	state := h.create("conn3x_windows_feature", cfg)
	if !winSynced(t, state) || !state.GetAttr("reboot_required").RawEquals(cty.True) {
		t.Fatalf("state %#v", state)
	}
	got := h.sent("apply_feature.ps1")
	if len(got) != 1 || got[0]["name"] != "Web-Server" || got[0]["present"] != true || got[0]["management_tools"] != true || got[0]["sub_features"] != false {
		t.Fatalf("apply sent %v", got)
	}
	if r := h.sent("read_feature.ps1"); r[0]["management_tools"] != true {
		t.Errorf("the read didn't ask for the tools: %v", r)
	}
	// A tool missing is drift.
	h.on("read_feature.ps1", map[string]any{"exists": true, "state": "Installed", "installed": true, "missing": []string{"Web-Mgmt-Console"}})
	if r := h.read("conn3x_windows_feature", state); winSynced(t, r.NewState) {
		t.Error("a missing tool read as in sync")
	}
	// Installed but waiting for its reboot: in sync, and the reboot is still wanted.
	h.on("read_feature.ps1", map[string]any{"exists": true, "state": "InstallPending"})
	if s := h.create("conn3x_windows_feature", cfg); !s.GetAttr("reboot_required").RawEquals(cty.True) || len(h.sent("apply_feature.ps1")) != 1 {
		t.Errorf("a pending install: %#v, applied %d", s.GetAttr("reboot_required"), len(h.sent("apply_feature.ps1")))
	}
	h.on("read_feature.ps1", map[string]any{"exists": false})
	if r := h.read("conn3x_windows_feature", state); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "no feature named Web-Server") {
		t.Errorf("a feature Windows doesn't have: %v", r.Diagnostics.Err())
	}
	// Removing the step never uninstalls.
	if r := h.destroy("conn3x_windows_feature", state); r.Diagnostics.HasErrors() || len(h.sent("apply_feature.ps1")) != 1 {
		t.Errorf("remove: %v", r.Diagnostics.Err())
	}
}

func TestWinFeatureRemoveAndFailures(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("apply_feature.ps1", map[string]any{"restart": false})
	winSysSeq(h, "read_feature.ps1",
		map[string]any{"exists": true, "state": "Installed", "installed": true},
		map[string]any{"exists": true, "state": "Removed"})
	cfg := h.step("conn3x_windows_feature", map[string]cty.Value{"name": cty.StringVal("Telnet-Client"), "state": cty.StringVal("absent"), "include_sub_features": cty.True})
	state := h.create("conn3x_windows_feature", cfg)
	if !state.GetAttr("reboot_required").RawEquals(cty.False) {
		t.Errorf("reboot_required = %#v", state.GetAttr("reboot_required"))
	}
	// Sub-features mean nothing to a removal's read.
	if got := h.sent("apply_feature.ps1"); got[0]["present"] != false || h.sent("read_feature.ps1")[0]["sub_features"] != false {
		t.Errorf("apply sent %v, read %v", got, h.sent("read_feature.ps1"))
	}

	h.on("read_feature.ps1", map[string]any{"exists": true, "state": "Installed", "installed": true})
	winSysErr(t, winSysApply(h, "conn3x_windows_feature", cfg), "doesn't match what was asked")
	h.fail("apply_feature.ps1", "source files not found")
	winSysErr(t, winSysApply(h, "conn3x_windows_feature", cfg), "changing Telnet-Client: source files not found")
	h.on("apply_feature.ps1", "no")
	winSysErr(t, winSysApply(h, "conn3x_windows_feature", cfg), "reading the result for feature Telnet-Client")
	h.fail("read_feature.ps1", "servicing busy")
	winSysErr(t, winSysApply(h, "conn3x_windows_feature", cfg), "servicing busy")

	planned := h.plan("conn3x_windows_feature", cty.NullVal(cfg.Type()), cfg).PlannedState
	for attr, bad := range map[string]cty.Value{"name": cty.StringVal("Web Server"), "timeout": cty.StringVal("later")} {
		vals := planned.AsValueMap()
		vals[attr] = bad
		r := resourceTypes["conn3x_windows_feature"].apply(context.Background(), providers.ApplyResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), PlannedState: cty.ObjectVal(vals), Config: cfg})
		winSysErr(t, r, "windows_feature:")
	}
}

func TestWinUpdateLifecycle(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("read_updates.ps1", map[string]any{"pending": []string{"KB5034441 2026-11 Cumulative Update"}})
	h.on("apply_updates.ps1", map[string]any{"installed": []string{"KB5034441"}, "restart": true})
	cfg := h.step("conn3x_windows_update", map[string]cty.Value{"reject_list": cty.ListVal([]cty.Value{cty.StringVal("KB5000001")})})
	state := h.create("conn3x_windows_update", cfg)
	if !winSynced(t, state) || state.GetAttr("pending").LengthInt() != 0 || !state.GetAttr("reboot_required").RawEquals(cty.True) {
		t.Fatalf("state %#v", state)
	}
	got := h.sent("apply_updates.ps1")
	if len(got) != 1 || got[0]["timeout_seconds"] != float64(7200) || fmt.Sprint(got[0]["reject"]) != "[KB5000001]" ||
		fmt.Sprint(got[0]["categories"]) != fmt.Sprintf("[%s %s]", windows.UpdateCategories["CriticalUpdates"], windows.UpdateCategories["SecurityUpdates"]) {
		t.Fatalf("apply sent %v", got)
	}
	r := h.read("conn3x_windows_update", state)
	if r.Diagnostics.HasErrors() || winSynced(t, r.NewState) || r.NewState.GetAttr("pending").LengthInt() != 1 {
		t.Errorf("an update waiting: %v %#v", r.Diagnostics.Err(), r.NewState)
	}
	h.on("read_updates.ps1", map[string]any{})
	if r := h.read("conn3x_windows_update", state); !winSynced(t, r.NewState) || !r.NewState.GetAttr("pending").RawEquals(cty.ListValEmpty(cty.String)) {
		t.Errorf("nothing waiting: %#v", r.NewState)
	}
	h.fail("read_updates.ps1", "the update service is off")
	if r := h.read("conn3x_windows_update", state); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "windows_update: the update service is off") {
		t.Errorf("a failed search: %v", r.Diagnostics.Err())
	}

	// Some installed and some didn't: the error names those that didn't.
	h.on("apply_updates.ps1", map[string]any{"installed": []string{"KB1"}, "failed": []string{"KB5034441 0x80070643"}})
	winSysErr(t, winSysApply(h, "conn3x_windows_update", cfg), "these updates didn't install: KB5034441 0x80070643")
	if r := h.destroy("conn3x_windows_update", state); r.Diagnostics.HasErrors() || len(h.applied()) != 2 {
		t.Errorf("remove ran %v: %v", h.applied(), r.Diagnostics.Err())
	}
}

// The plan of a new windows_update step names what its apply would install.
func TestWinUpdatePlanListsTheUpdates(t *testing.T) {
	h := newWinFakeHost(t)
	cfg := h.step("conn3x_windows_update", map[string]cty.Value{"categories": cty.ListVal([]cty.Value{cty.StringVal("Drivers")})})
	warning := func() string {
		req := providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}
		resp := planWinUpdate(req)
		planWinUpdateReads(context.Background(), req, &resp)
		if resp.Diagnostics.HasErrors() || len(resp.Diagnostics) != 1 {
			t.Fatalf("diagnostics %v", resp.Diagnostics)
		}
		return resp.Diagnostics[0].Description().Summary
	}
	h.on("read_updates.ps1", map[string]any{"pending": []string{"KB1000001 Driver A", "KB1000002 Driver B"}})
	if w := warning(); !strings.Contains(w, "installs these 2 updates") || !strings.Contains(w, "KB1000002 Driver B") {
		t.Errorf("warning %q", w)
	}
	if got := h.sent("read_updates.ps1"); fmt.Sprint(got[0]["categories"]) != "["+windows.UpdateCategories["Drivers"]+"]" {
		t.Errorf("searched %v", got)
	}
	h.on("read_updates.ps1", map[string]any{"pending": []string{}})
	if w := warning(); !strings.Contains(w, "installs nothing") {
		t.Errorf("warning %q", w)
	}
	h.fail("read_updates.ps1", "offline")
	if w := warning(); !strings.Contains(w, "couldn't list the updates") || !strings.Contains(w, "offline") {
		t.Errorf("warning %q", w)
	}

	// A host that can't be reached yet says nothing.
	vals := cfg.AsValueMap()
	conn := h.conn.AsValueMap()
	conn["port"] = cty.NumberIntVal(1)
	conn["timeout"] = cty.StringVal("1s")
	vals["ssh"] = cty.ObjectVal(conn)
	away := cty.ObjectVal(vals)
	req := providers.PlanResourceChangeRequest{PriorState: cty.NullVal(away.Type()), ProposedNewState: away, Config: away}
	resp := planWinUpdate(req)
	planWinUpdateReads(context.Background(), req, &resp)
	if len(resp.Diagnostics) != 0 {
		t.Errorf("an unreachable host: %v", resp.Diagnostics)
	}
}
