// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestWinUserLifecycle(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	h := newWinFakeHost(t)
	h.on("apply_user.ps1", nil)
	alice := map[string]any{"exists": true, "sid": "S-1-5-21-1-1001", "full_name": "Alice A", "enabled": true, "password_set": true}
	winSysSeq(h, "read_user.ps1", map[string]any{"exists": false}, alice)
	cfg := h.step("conn3x_windows_user", map[string]cty.Value{
		"name": cty.StringVal("alice"), "full_name": cty.StringVal("Alice A"), "password_wo": cty.StringVal("Pa55word!"), "on_remove": cty.StringVal("delete"),
	})
	state := h.create("conn3x_windows_user", cfg)
	if !winSynced(t, state) || !known(state.GetAttr("password_hmac")) || strings.Contains(fmt.Sprintf("%#v", state), "Pa55word!") {
		t.Fatalf("state %#v", state)
	}
	got := h.sent("apply_user.ps1")
	if len(got) != 1 || got[0]["name"] != "alice" || got[0]["create"] != true || got[0]["full_name"] != "Alice A" || got[0]["password"] != "Pa55word!" || got[0]["disabled"] != nil {
		t.Fatalf("apply sent %v", got)
	}

	// The same password isn't set again: Windows can refuse to reuse one.
	if r := h.update("conn3x_windows_user", state, cfg); r.Diagnostics.HasErrors() || len(h.sent("apply_user.ps1")) != 1 {
		t.Errorf("an unchanged user was changed: %v %v", r.Diagnostics.Err(), h.sent("apply_user.ps1"))
	}
	// Unless the user was deleted behind Conn3x's back.
	winSysSeq(h, "read_user.ps1", map[string]any{"exists": false}, alice)
	if r := h.update("conn3x_windows_user", state, cfg); r.Diagnostics.HasErrors() {
		t.Fatal(r.Diagnostics.Err())
	}
	if got := h.sent("apply_user.ps1"); len(got) != 2 || got[1]["create"] != true || got[1]["password"] != "Pa55word!" {
		t.Errorf("remade with %v", got)
	}

	if r := h.read("conn3x_windows_user", state); !winSynced(t, r.NewState) {
		t.Error("a matching user read as out of sync")
	}
	h.on("read_user.ps1", map[string]any{"exists": true, "full_name": "Someone Else", "enabled": true})
	if r := h.read("conn3x_windows_user", state); winSynced(t, r.NewState) {
		t.Error("a changed full name read as in sync")
	}
	h.on("read_user.ps1", 7)
	if r := h.read("conn3x_windows_user", state); !r.Diagnostics.HasErrors() {
		t.Error("a malformed answer read without error")
	}

	h.on("apply_user_remove.ps1", nil)
	if r := h.destroy("conn3x_windows_user", state); r.Diagnostics.HasErrors() {
		t.Fatal(r.Diagnostics.Err())
	}
	if got := h.sent("apply_user_remove.ps1"); len(got) != 1 || got[0]["name"] != "alice" {
		t.Errorf("remove sent %v", got)
	}
	h.fail("apply_user_remove.ps1", "user is logged on")
	winSysErr(t, h.destroy("conn3x_windows_user", state), "windows_user: user is logged on")
}

func TestWinUserApplyFailures(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("read_user.ps1", map[string]any{"exists": false})
	cfg := h.step("conn3x_windows_user", map[string]cty.Value{"name": cty.StringVal("bob")})
	// Windows lets a blank password log on at the console.
	winSysErr(t, winSysApply(h, "conn3x_windows_user", cfg), "would be enabled with no password")
	if len(h.applied()) != 0 {
		t.Errorf("ran %v", h.applied())
	}

	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	pw := h.step("conn3x_windows_user", map[string]cty.Value{"name": cty.StringVal("bob"), "password_wo": cty.StringVal("short")})
	h.fail("apply_user.ps1", "Exception: Microsoft.PowerShell.Commands.InvalidPasswordException: short")
	r := winSysApply(h, "conn3x_windows_user", pw)
	winSysErr(t, r, "doesn't meet the password policy")
	h.fail("apply_user.ps1", "could not set short as the password")
	r = winSysApply(h, "conn3x_windows_user", pw)
	if winSysErr(t, r, "windows_user:"); strings.Contains(r.Diagnostics.Err().Error(), "short") {
		t.Errorf("the password reached the error: %v", r.Diagnostics.Err())
	}

	h.on("apply_user.ps1", nil)
	winSysErr(t, winSysApply(h, "conn3x_windows_user", pw), "doesn't match what was set")
	h.fail("read_user.ps1", "access denied")
	winSysErr(t, winSysApply(h, "conn3x_windows_user", pw), "windows_user: access denied")
}

// The login Conn3x uses is never disabled or deleted, whatever the plan says.
func TestWinUserNeverLocksConn3xOut(t *testing.T) {
	h := newWinFakeHost(t)
	cfg := h.step("conn3x_windows_user", map[string]cty.Value{"name": cty.StringVal("administrator"), "disabled": cty.True})
	winSysErr(t, winSysApply(h, "conn3x_windows_user", cfg), "would lock Conn3x out")

	state := h.plan("conn3x_windows_user", cty.NullVal(cfg.Type()), h.step("conn3x_windows_user", map[string]cty.Value{"name": cty.StringVal("Administrator")})).PlannedState
	vals := state.AsValueMap()
	vals["on_remove"], vals["in_sync"] = cty.StringVal("delete"), cty.True
	winSysErr(t, h.destroy("conn3x_windows_user", cty.ObjectVal(vals)), "deleting it would lock Conn3x out")
	if len(h.sent("read_user.ps1"))+len(h.applied()) != 0 {
		t.Error("a lockout reached the host")
	}
	if !resourceTypes["conn3x_windows_user"].validate(cty.ObjectVal(vals)).HasErrors() {
		t.Error("validate accepted deleting the login")
	}
}

func TestWinGroupLifecycle(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("apply_group.ps1", nil)
	sids := map[string]any{`LAB\alice`: "S-1-5-21-1-1001"}
	winSysSeq(h, "read_group.ps1",
		map[string]any{"exists": false, "sids": sids},
		map[string]any{"exists": true, "description": "Ops", "members": []string{"S-1-5-21-1-1001"}, "sids": sids})
	cfg := h.step("conn3x_windows_group", map[string]cty.Value{
		"name": cty.StringVal("Ops"), "description": cty.StringVal("Ops"), "members": cty.SetVal([]cty.Value{cty.StringVal(`LAB\alice`)}), "on_remove": cty.StringVal("delete"),
	})
	state := h.create("conn3x_windows_group", cfg)
	if !winSynced(t, state) {
		t.Error("a made group isn't in sync")
	}
	got := h.sent("apply_group.ps1")
	if len(got) != 1 || got[0]["create"] != true || got[0]["description"] != "Ops" || fmt.Sprint(got[0]["add"]) != "[S-1-5-21-1-1001]" || got[0]["remove"] != nil {
		t.Fatalf("apply sent %v", got)
	}
	if r := h.sent("read_group.ps1"); fmt.Sprint(r[0]["principals"]) != `[LAB\alice]` {
		t.Errorf("read sent %v", r)
	}
	if r := h.read("conn3x_windows_group", state); !winSynced(t, r.NewState) {
		t.Error("a matching group read as out of sync")
	}
	// Someone else in the group is fine unless the list is authoritative.
	h.on("read_group.ps1", map[string]any{"exists": true, "description": "Ops", "members": []string{"S-1-5-21-1-1001", "S-1-5-21-1-1002"}, "sids": sids})
	if r := h.read("conn3x_windows_group", state); !winSynced(t, r.NewState) {
		t.Error("an extra member read as drift")
	}
	auth := h.step("conn3x_windows_group", map[string]cty.Value{"name": cty.StringVal("Ops"), "members": cty.SetVal([]cty.Value{cty.StringVal(`LAB\alice`)}), "authoritative": cty.True})
	winSysSeq(h, "read_group.ps1",
		map[string]any{"exists": true, "members": []string{"S-1-5-21-1-1001", "S-1-5-21-1-1002"}, "sids": sids},
		map[string]any{"exists": true, "members": []string{"S-1-5-21-1-1001"}, "sids": sids})
	h.create("conn3x_windows_group", auth)
	if got := h.sent("apply_group.ps1"); len(got) != 2 || got[1]["create"] != false || fmt.Sprint(got[1]["remove"]) != "[S-1-5-21-1-1002]" || got[1]["add"] != nil {
		t.Errorf("authoritative sent %v", got)
	}

	h.on("apply_group_remove.ps1", nil)
	if r := h.destroy("conn3x_windows_group", state); r.Diagnostics.HasErrors() {
		t.Fatal(r.Diagnostics.Err())
	}
	if got := h.sent("apply_group_remove.ps1"); len(got) != 1 || got[0]["name"] != "Ops" {
		t.Errorf("remove sent %v", got)
	}
	h.fail("apply_group_remove.ps1", "group in use")
	winSysErr(t, h.destroy("conn3x_windows_group", state), "windows_group: group in use")
	h.fail("read_group.ps1", "SAM unavailable")
	if r := h.read("conn3x_windows_group", state); !r.Diagnostics.HasErrors() {
		t.Error("a failed read reported no error")
	}
}

func TestWinGroupApplyFailures(t *testing.T) {
	h := newWinFakeHost(t)
	cfg := h.step("conn3x_windows_group", map[string]cty.Value{"name": cty.StringVal("Ops"), "members": cty.SetVal([]cty.Value{cty.StringVal("nobody")})})
	// A member an earlier step hasn't made yet only fails at apply.
	h.on("read_group.ps1", map[string]any{"exists": true, "sids": map[string]any{}})
	winSysErr(t, winSysApply(h, "conn3x_windows_group", cfg), "no account named nobody")
	h.on("read_group.ps1", map[string]any{"exists": true, "sids": map[string]any{"nobody": "1; rm"}})
	winSysErr(t, winSysApply(h, "conn3x_windows_group", cfg), `gave "1; rm" as a SID`)
	if len(h.applied()) != 0 {
		t.Errorf("ran %v", h.applied())
	}
	h.on("read_group.ps1", map[string]any{"exists": true, "sids": map[string]any{"nobody": "S-1-5-21-9"}})
	h.on("apply_group.ps1", nil)
	winSysErr(t, winSysApply(h, "conn3x_windows_group", cfg), "doesn't match what was set")
	h.fail("apply_group.ps1", "member not found")
	winSysErr(t, winSysApply(h, "conn3x_windows_group", cfg), "windows_group: member not found")
	h.on("read_group.ps1", "[")
	winSysErr(t, winSysApply(h, "conn3x_windows_group", cfg), "the host's answer wasn't valid")
}
