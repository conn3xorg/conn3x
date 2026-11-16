// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

// newWinADHost is a fake domain controller whose AD answers at once.
func newWinADHost(t *testing.T) *winFakeHost {
	h := newWinFakeHost(t)
	h.on("read_ad_ready.ps1", "")
	return h
}

func winADErr(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("got %v, want %q", err, want)
	}
}

func TestWinADOULifecycle(t *testing.T) {
	h := newWinADHost(t)
	made := map[string]any{"ad": true, "base": "DC=lab,DC=test", "exists": true, "dn": "OU=Servers,DC=lab,DC=test", "description": "Web tier", "protected": true}
	winADSeq(h, "read_ad_ou.ps1", map[string]any{"ad": true, "base": "DC=lab,DC=test"}, made)
	h.on("apply_ad_ou.ps1", nil)
	h.on("apply_ad_ou_remove.ps1", nil)
	cfg := h.step("conn3x_windows_ad_ou", map[string]cty.Value{"name": cty.StringVal("Servers"), "description": cty.StringVal("Web tier"), "on_remove": cty.StringVal("delete")})
	state := h.create("conn3x_windows_ad_ou", cfg)
	if !winSynced(t, state) {
		t.Error("a new OU isn't in sync")
	}
	got := h.sent("apply_ad_ou.ps1")
	if len(got) != 1 || got[0]["create"] != true || got[0]["name"] != "Servers" || got[0]["path"] != "DC=lab,DC=test" || got[0]["description"] != "Web tier" || got[0]["protected"] != nil {
		t.Fatalf("apply sent %v", got)
	}
	if args := h.sent("read_ad_ou.ps1")[0]; args["name"] != "Servers" || args["path"] != "" {
		t.Errorf("read sent %v", args)
	}
	if r := h.read("conn3x_windows_ad_ou", state); !winSynced(t, r.NewState) {
		t.Error("an unchanged OU read as out of sync")
	}

	// Drift is put right on the OU that's there, by its DN.
	h.on("read_ad_ou.ps1", map[string]any{"ad": true, "exists": true, "dn": "OU=Servers,DC=lab,DC=test", "description": "edited"})
	if r := h.read("conn3x_windows_ad_ou", state); winSynced(t, r.NewState) {
		t.Error("a changed description read as in sync")
	}
	r := h.update("conn3x_windows_ad_ou", state, cfg)
	winADErr(t, r.Diagnostics.Err(), "OU Servers doesn't match what was set")
	if got := h.sent("apply_ad_ou.ps1"); len(got) != 2 || got[1]["create"] != false || got[1]["dn"] != "OU=Servers,DC=lab,DC=test" {
		t.Errorf("update sent %v", got)
	}

	if r := h.destroy("conn3x_windows_ad_ou", state); r.Diagnostics.HasErrors() {
		t.Fatal(r.Diagnostics.Err())
	}
	if got := h.sent("apply_ad_ou_remove.ps1"); len(got) != 1 || got[0]["dn"] != "OU=Servers,DC=lab,DC=test" {
		t.Errorf("remove sent %v", got)
	}
	// One already gone is nothing to do.
	h.on("read_ad_ou.ps1", map[string]any{"ad": true})
	if r := h.destroy("conn3x_windows_ad_ou", state); r.Diagnostics.HasErrors() || len(h.sent("apply_ad_ou_remove.ps1")) != 1 {
		t.Errorf("removed a missing OU: %v", r.Diagnostics.Err())
	}
	h.fail("apply_ad_ou_remove.ps1", "the OU isn't empty")
	h.on("read_ad_ou.ps1", made)
	winADErr(t, h.destroy("conn3x_windows_ad_ou", state).Diagnostics.Err(), "windows_ad_ou: the OU isn't empty")
}

func TestWinADOURefusals(t *testing.T) {
	h := newWinADHost(t)
	cfg := h.step("conn3x_windows_ad_ou", map[string]cty.Value{"name": cty.StringVal("Servers"), "path": cty.StringVal("OU=Lab,DC=lab,DC=test")})
	h.on("read_ad_ou.ps1", map[string]any{"ad": false})
	winADErr(t, h.update("conn3x_windows_ad_ou", cty.NullVal(cfg.Type()), cfg).Diagnostics.Err(), "isn't a domain controller")
	h.on("read_ad_ou.ps1", map[string]any{"ad": true})
	winADErr(t, h.update("conn3x_windows_ad_ou", cty.NullVal(cfg.Type()), cfg).Diagnostics.Err(), "the path OU=Lab,DC=lab,DC=test doesn't exist")
	h.on("read_ad_ou.ps1", "?")
	winADErr(t, h.update("conn3x_windows_ad_ou", cty.NullVal(cfg.Type()), cfg).Diagnostics.Err(), "reading OU Servers: the host's answer wasn't valid")
	if r := h.read("conn3x_windows_ad_ou", cfg); !r.Diagnostics.HasErrors() {
		t.Error("refresh: a malformed answer reported no error")
	}
	if a := h.applied(); len(a) != 0 {
		t.Errorf("ran %v", a)
	}
}

func TestWinADGroupLifecycle(t *testing.T) {
	h := newWinADHost(t)
	alice := map[string]any{"dn": "CN=alice,CN=Users,DC=lab,DC=test", "sid": "S-1-5-21-1-1001"}
	contact := map[string]any{"dn": "CN=bob,CN=Users,DC=lab,DC=test"}
	wanted := map[string]any{"alice": alice, "bob": contact}
	winADSeq(h, "read_ad_group.ps1",
		map[string]any{"ad": true, "path_dn": "OU=Groups,DC=lab,DC=test", "wanted": wanted},
		map[string]any{"ad": true, "exists": true, "dn": "CN=Ops,OU=Groups,DC=lab,DC=test", "parent": "OU=Groups,DC=lab,DC=test", "path_dn": "OU=Groups,DC=lab,DC=test",
			"scope": "Universal", "category": "Security", "members": []any{alice, contact}, "wanted": wanted})
	h.on("apply_ad_group.ps1", nil)
	h.on("apply_ad_group_remove.ps1", nil)
	cfg := h.step("conn3x_windows_ad_group", map[string]cty.Value{
		"name": cty.StringVal("Ops"), "path": cty.StringVal("OU=Groups,DC=lab,DC=test"), "scope": cty.StringVal("universal"),
		"members": cty.SetVal([]cty.Value{cty.StringVal("alice"), cty.StringVal("bob")}), "authoritative": cty.True, "on_remove": cty.StringVal("delete"),
	})
	state := h.create("conn3x_windows_ad_group", cfg)
	if !winSynced(t, state) || state.GetAttr("pending_changes").LengthInt() != 0 {
		t.Fatalf("state %#v", state)
	}
	got := h.sent("apply_ad_group.ps1")
	// Added by SID where there is one, by DN where there isn't.
	if len(got) != 1 || got[0]["create"] != true || got[0]["scope"] != "universal" || strings.Join(winADStrings(got[0]["add"]), " ") != "<SID=S-1-5-21-1-1001> CN=bob,CN=Users,DC=lab,DC=test" {
		t.Fatalf("apply sent %v", got)
	}
	if r := h.read("conn3x_windows_ad_group", state); !winSynced(t, r.NewState) {
		t.Error("an unchanged group read as out of sync")
	}

	// Someone added carol by hand, and bob's account went: the refresh says
	// what an apply would do.
	carol := map[string]any{"dn": "CN=carol,CN=Users,DC=lab,DC=test", "sid": "S-1-5-21-1-1003"}
	h.on("read_ad_group.ps1", map[string]any{"ad": true, "exists": true, "dn": "CN=Ops,OU=Groups,DC=lab,DC=test", "parent": "OU=Groups,DC=lab,DC=test", "path_dn": "OU=Groups,DC=lab,DC=test",
		"members": []any{alice, carol}, "wanted": map[string]any{"alice": alice, "bob": map[string]any{}}})
	r := h.read("conn3x_windows_ad_group", state)
	if winSynced(t, r.NewState) {
		t.Error("a drifted group read as in sync")
	}
	var pending []string
	for _, v := range r.NewState.GetAttr("pending_changes").AsValueSlice() {
		pending = append(pending, v.AsString())
	}
	if strings.Join(pending, "|") != "remove CN=carol,CN=Users,DC=lab,DC=test|not found bob" {
		t.Errorf("pending_changes = %q", pending)
	}
	winADErr(t, h.update("conn3x_windows_ad_group", r.NewState, cfg).Diagnostics.Err(), "no account named bob")

	if r := h.destroy("conn3x_windows_ad_group", state); r.Diagnostics.HasErrors() {
		t.Fatal(r.Diagnostics.Err())
	}
	if got := h.sent("apply_ad_group_remove.ps1"); len(got) != 1 || got[0]["dn"] != "CN=Ops,OU=Groups,DC=lab,DC=test" {
		t.Errorf("remove sent %v", got)
	}
}

func TestWinADGroupMovesAndRefusals(t *testing.T) {
	h := newWinADHost(t)
	h.on("apply_ad_group.ps1", nil)
	cfg := h.step("conn3x_windows_ad_group", map[string]cty.Value{"name": cty.StringVal("Ops"), "path": cty.StringVal("OU=Groups,DC=lab,DC=test")})
	// Found in CN=Users: moved, and the read after shows it still there.
	h.on("read_ad_group.ps1", map[string]any{"ad": true, "exists": true, "dn": "CN=Ops,CN=Users,DC=lab,DC=test", "parent": "CN=Users,DC=lab,DC=test", "path_dn": "OU=Groups,DC=lab,DC=test"})
	winADErr(t, h.update("conn3x_windows_ad_group", cty.NullVal(cfg.Type()), cfg).Diagnostics.Err(), "group Ops doesn't match what was set")
	if got := h.sent("apply_ad_group.ps1"); len(got) != 1 || got[0]["move"] != true || got[0]["create"] != false {
		t.Errorf("apply sent %v", got)
	}
	h.on("read_ad_group.ps1", map[string]any{"ad": true})
	winADErr(t, h.update("conn3x_windows_ad_group", cty.NullVal(cfg.Type()), cfg).Diagnostics.Err(), "the path OU=Groups,DC=lab,DC=test doesn't exist")
	h.on("read_ad_group.ps1", map[string]any{"ad": false})
	winADErr(t, h.update("conn3x_windows_ad_group", cty.NullVal(cfg.Type()), cfg).Diagnostics.Err(), "isn't a domain controller")
	h.fail("read_ad_group.ps1", "the server is not operational")
	if r := h.read("conn3x_windows_ad_group", cfg); !r.Diagnostics.HasErrors() {
		t.Error("refresh: a failed read reported no error")
	}
	if n := len(h.applied()); n != 1 {
		t.Errorf("%d applies", n)
	}
}

func winADStrings(v any) []string {
	var out []string
	for _, s := range v.([]any) {
		out = append(out, s.(string))
	}
	return out
}

func TestWinADUserLifecycle(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	h := newWinADHost(t)
	made := map[string]any{"ad": true, "exists": true, "dn": "CN=alice,CN=Users,DC=lab,DC=test", "upn": "alice@lab.test", "display_name": "Alice", "enabled": true, "password_set": true}
	winADSeq(h, "read_ad_user.ps1", map[string]any{"ad": true}, made)
	h.on("apply_ad_user.ps1", nil)
	h.on("apply_ad_user_remove.ps1", nil)
	cfg := h.step("conn3x_windows_ad_user", map[string]cty.Value{
		"name": cty.StringVal("alice"), "upn": cty.StringVal("alice@lab.test"), "display_name": cty.StringVal("Alice"),
		"password_wo": cty.StringVal("ad-s3cret"), "on_remove": cty.StringVal("delete"),
	})
	state := h.create("conn3x_windows_ad_user", cfg)
	if !winSynced(t, state) || state.GetAttr("password_hmac").IsNull() || !state.GetAttr("password_wo").IsNull() || strings.Contains(state.GoString(), "ad-s3cret") {
		t.Fatalf("state %#v", state)
	}
	got := h.sent("apply_ad_user.ps1")
	// A new user with a password is enabled.
	if len(got) != 1 || got[0]["create"] != true || got[0]["password"] != "ad-s3cret" || got[0]["enabled"] != true || got[0]["upn"] != "alice@lab.test" || got[0]["given_name"] != nil {
		t.Fatalf("apply sent %v", got)
	}
	if r := h.read("conn3x_windows_ad_user", state); !winSynced(t, r.NewState) {
		t.Error("an unchanged user read as out of sync")
	}

	// The same password and settings: nothing to write.
	if r := h.update("conn3x_windows_ad_user", state, cfg); r.Diagnostics.HasErrors() || len(h.sent("apply_ad_user.ps1")) != 1 {
		t.Errorf("rewrote an unchanged user: %v", r.Diagnostics.Err())
	}
	// Deleted behind Conn3x's back: made again, with its password.
	winADSeq(h, "read_ad_user.ps1", map[string]any{"ad": true}, made)
	if r := h.update("conn3x_windows_ad_user", state, cfg); r.Diagnostics.HasErrors() {
		t.Fatal(r.Diagnostics.Err())
	}
	if got := h.sent("apply_ad_user.ps1"); len(got) != 2 || got[1]["create"] != true || got[1]["password"] != "ad-s3cret" {
		t.Errorf("remade with %v", got)
	}
	// Drift, put right by DN, without the password.
	h.on("read_ad_user.ps1", map[string]any{"ad": true, "exists": true, "dn": "CN=alice,CN=Users,DC=lab,DC=test", "upn": "alice@lab.test", "display_name": "A", "enabled": true, "password_set": true})
	if r := h.read("conn3x_windows_ad_user", state); winSynced(t, r.NewState) {
		t.Error("a changed display name read as in sync")
	}
	winADErr(t, h.update("conn3x_windows_ad_user", state, cfg).Diagnostics.Err(), "user alice doesn't match what was set")
	if got := h.sent("apply_ad_user.ps1"); len(got) != 3 || got[2]["create"] != false || got[2]["password"] != nil || got[2]["dn"] != "CN=alice,CN=Users,DC=lab,DC=test" {
		t.Errorf("update sent %v", got)
	}

	h.on("read_ad_user.ps1", made)
	if r := h.destroy("conn3x_windows_ad_user", state); r.Diagnostics.HasErrors() {
		t.Fatal(r.Diagnostics.Err())
	}
	if got := h.sent("apply_ad_user_remove.ps1"); len(got) != 1 || got[0]["dn"] != "CN=alice,CN=Users,DC=lab,DC=test" {
		t.Errorf("remove sent %v", got)
	}
}

func TestWinADUserRefusals(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	h := newWinADHost(t)
	h.on("read_ad_user.ps1", map[string]any{"ad": true})
	with := func(attrs map[string]cty.Value) cty.Value {
		attrs["name"] = cty.StringVal("bob")
		return h.step("conn3x_windows_ad_user", attrs)
	}
	create := func(cfg cty.Value) error {
		return h.update("conn3x_windows_ad_user", cty.NullVal(cfg.Type()), cfg).Diagnostics.Err()
	}
	// Never enabled before it has a password.
	winADErr(t, create(with(map[string]cty.Value{"enabled": cty.True})), "would be enabled with no password")
	winADErr(t, create(with(map[string]cty.Value{"path": cty.StringVal("OU=Gone,DC=lab,DC=test")})), "the path OU=Gone,DC=lab,DC=test doesn't exist")
	h.fail("apply_ad_user.ps1", "The password does not meet the length, complexity, or history requirement of the domain.")
	winADErr(t, create(with(map[string]cty.Value{"password_wo": cty.StringVal("short")})), "the domain refused the password")
	h.fail("apply_ad_user.ps1", "rejected bob-s3cret")
	err := create(with(map[string]cty.Value{"password_wo": cty.StringVal("bob-s3cret")}))
	if err == nil || strings.Contains(err.Error(), "bob-s3cret") {
		t.Errorf("got %v", err)
	}
	h.on("read_ad_user.ps1", map[string]any{"ad": false})
	winADErr(t, create(with(map[string]cty.Value{"enabled": cty.False})), "isn't a domain controller")

	// The login itself: never disabled, never deleted, and nothing connects
	// to find that out.
	n := len(h.applied())
	login := h.step("conn3x_windows_ad_user", map[string]cty.Value{"name": cty.StringVal("administrator"), "enabled": cty.False})
	winADErr(t, create(login), "disabling it would lock Conn3x out")
	vals := h.step("conn3x_windows_ad_user", map[string]cty.Value{"name": cty.StringVal("Administrator")}).AsValueMap()
	vals["on_remove"] = cty.StringVal("delete")
	winADErr(t, h.destroy("conn3x_windows_ad_user", cty.ObjectVal(vals)).Diagnostics.Err(), "deleting it would lock Conn3x out")
	if len(h.applied()) != n {
		t.Errorf("ran %v", h.applied())
	}
}
