// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestWinEnvLifecycle(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("apply_env.ps1", nil)
	cfg := h.step("conn3x_windows_environment", map[string]cty.Value{
		"name": cty.StringVal("JAVA_HOME"), "value": cty.StringVal(`%ProgramFiles%\Java`), "level": cty.StringVal("user"), "on_remove": cty.StringVal("delete"),
	})
	state := h.create("conn3x_windows_environment", cfg)
	if !winSynced(t, state) {
		t.Error("a created variable isn't in sync")
	}
	got := h.sent("apply_env.ps1")
	if len(got) != 1 || got[0]["key"] != "Environment" || got[0]["name"] != "JAVA_HOME" || got[0]["value"] != `%ProgramFiles%\Java` || got[0]["user"] != true || got[0]["absent"] != false {
		t.Fatalf("apply sent %v", got)
	}

	// The value is compared as written, unexpanded.
	h.on("read_env.ps1", map[string]any{"exists": true, "kind": "ExpandString", "value": `%ProgramFiles%\Java`})
	if r := h.read("conn3x_windows_environment", state); r.Diagnostics.HasErrors() || !winSynced(t, r.NewState) {
		t.Errorf("unchanged variable: %v %#v", r.Diagnostics.Err(), r.NewState.GetAttr("in_sync"))
	}
	h.on("read_env.ps1", map[string]any{"exists": true, "kind": "String", `value`: `C:\Program Files\Java`})
	if r := h.read("conn3x_windows_environment", state); winSynced(t, r.NewState) {
		t.Error("an expanded value read as in sync")
	}
	h.on("read_env.ps1", "not an object")
	if r := h.read("conn3x_windows_environment", state); !r.Diagnostics.HasErrors() {
		t.Error("a malformed answer read without error")
	}

	// on_remove = "delete" removes it, at the level it was made.
	if r := h.destroy("conn3x_windows_environment", state); r.Diagnostics.HasErrors() {
		t.Fatal(r.Diagnostics.Err())
	}
	if got := h.sent("apply_env.ps1"); len(got) != 2 || got[1]["absent"] != true || got[1]["user"] != true {
		t.Errorf("delete sent %v", got)
	}
}

func TestWinEnvForgetAndHostErrors(t *testing.T) {
	h := newWinFakeHost(t)
	h.fail("apply_env.ps1", "Access is denied")
	cfg := h.step("conn3x_windows_environment", map[string]cty.Value{"name": cty.StringVal("A"), "value": cty.StringVal("1")})
	planned := h.plan("conn3x_windows_environment", cty.NullVal(cfg.Type()), cfg).PlannedState
	if planned.GetAttr("on_remove").AsString() != "forget" {
		t.Errorf("on_remove defaulted to %#v", planned.GetAttr("on_remove"))
	}
	r := h.update("conn3x_windows_environment", cty.NullVal(cfg.Type()), cfg)
	if !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "windows_environment: Access is denied") {
		t.Errorf("a host error: %v", r.Diagnostics.Err())
	}
	// The default, forget, leaves the host alone.
	vals := planned.AsValueMap()
	vals["in_sync"] = cty.True
	if r := h.destroy("conn3x_windows_environment", cty.ObjectVal(vals)); r.Diagnostics.HasErrors() || len(h.applied()) != 1 {
		t.Errorf("forget ran %v: %v", h.applied(), r.Diagnostics.Err())
	}
}

func TestWinEnvValidate(t *testing.T) {
	r := resourceTypes["conn3x_windows_environment"]
	if d := r.validate(objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("A"), "state": cty.StringVal("absent")})); d.HasErrors() {
		t.Error(d.Err())
	}
	for name, bad := range map[string]map[string]cty.Value{
		"no value":  {"name": cty.StringVal("A")},
		"path":      {"name": cty.StringVal("PATH"), "value": cty.StringVal("x")},
		"equals":    {"name": cty.StringVal("A=B"), "value": cty.StringVal("x")},
		"level":     {"name": cty.StringVal("A"), "value": cty.StringVal("x"), "level": cty.StringVal("system")},
		"state":     {"name": cty.StringVal("A"), "value": cty.StringVal("x"), "state": cty.StringVal("gone")},
		"on_remove": {"name": cty.StringVal("A"), "value": cty.StringVal("x"), "on_remove": cty.StringVal("keep")},
	} {
		if !r.validate(objFor(r.schema(), bad)).HasErrors() {
			t.Errorf("%s: accepted %v", name, bad)
		}
	}
}

// A Path entry is added after what's there, and removed alone, leaving the
// other folders in order.
func TestWinPathLifecycle(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("apply_env.ps1", nil)
	h.on("read_env.ps1", map[string]any{"exists": true, "kind": "ExpandString", "value": `C:\Windows;C:\Tools;`})
	cfg := h.step("conn3x_windows_path", map[string]cty.Value{"element": cty.StringVal(`C:\Go\bin`), "on_remove": cty.StringVal("delete")})
	state := h.create("conn3x_windows_path", cfg)
	got := h.sent("apply_env.ps1")
	if len(got) != 1 || got[0]["name"] != "Path" || got[0]["value"] != `C:\Windows;C:\Tools;C:\Go\bin` || got[0]["user"] != false {
		t.Fatalf("apply sent %v", got)
	}
	if r := h.read("conn3x_windows_path", state); winSynced(t, r.NewState) {
		t.Error("Path without the folder read as in sync")
	}
	h.on("read_env.ps1", map[string]any{"exists": true, "value": `C:\go\BIN\;C:\Windows;C:\Tools;C:\Go\bin`})
	if r := h.read("conn3x_windows_path", state); !winSynced(t, r.NewState) {
		t.Error("Path with the folder read as out of sync")
	}
	// Already there: nothing is written.
	h.create("conn3x_windows_path", cfg)
	if n := len(h.sent("apply_env.ps1")); n != 1 {
		t.Errorf("a folder already in Path wrote it %d times", n)
	}
	if r := h.destroy("conn3x_windows_path", state); r.Diagnostics.HasErrors() {
		t.Fatal(r.Diagnostics.Err())
	}
	if got := h.sent("apply_env.ps1"); len(got) != 2 || got[1]["value"] != `C:\Windows;C:\Tools` {
		t.Errorf("remove sent %v", got)
	}
	h.fail("read_env.ps1", "registry unavailable")
	if r := h.read("conn3x_windows_path", state); !r.Diagnostics.HasErrors() {
		t.Error("a failed read reported no error")
	}
	r := resourceTypes["conn3x_windows_path"]
	for _, bad := range []map[string]cty.Value{
		{"element": cty.StringVal(`C:\a;C:\b`)},
		{"element": cty.StringVal(`C:\a`), "scope": cty.StringVal("all")},
	} {
		if !r.validate(objFor(r.schema(), bad)).HasErrors() {
			t.Errorf("accepted %v", bad)
		}
	}
}
