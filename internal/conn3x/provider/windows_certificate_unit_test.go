// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func TestWinCertPFXLifecycle(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("apply_certificate.ps1", map[string]any{"thumbprint": "AB12", "sha256": "f00d"})
	cfg := h.step("conn3x_windows_certificate", map[string]cty.Value{
		"path": cty.StringVal(`C:\certs\web.pfx`), "store_name": cty.StringVal("My"), "password_wo": cty.StringVal("s3cret"), "on_remove": cty.StringVal("delete"),
	})
	state := h.create("conn3x_windows_certificate", cfg)
	if !winSynced(t, state) || state.GetAttr("thumbprint").AsString() != "AB12" || state.GetAttr("file_sha256").AsString() != "f00d" || !state.GetAttr("password_wo").IsNull() {
		t.Fatalf("state = %#v", state)
	}
	got := h.sent("apply_certificate.ps1")
	if len(got) != 1 || got[0]["password"] != "s3cret" || got[0]["pfx"] != true || got[0]["location"] != "LocalMachine" || got[0]["thumbprint"] != "" || got[0]["drop"] != false {
		t.Fatalf("apply sent %v", got)
	}

	// The refresh looks for the recorded thumbprint; a PFX without its key,
	// or a renewed file, is drift. A file deleted after the import isn't.
	for name, c := range map[string]struct {
		answer map[string]any
		synced bool
	}{
		"same":         {map[string]any{"in_store": true, "has_key": true, "file_exists": true, "file_sha256": "f00d"}, true},
		"file deleted": {map[string]any{"in_store": true, "has_key": true}, true},
		"renewed":      {map[string]any{"in_store": true, "has_key": true, "file_exists": true, "file_sha256": "beef"}, false},
		"no key":       {map[string]any{"in_store": true, "file_exists": true, "file_sha256": "f00d"}, false},
		"gone":         {map[string]any{"file_exists": true, "file_sha256": "f00d"}, false},
	} {
		h.on("read_certificate.ps1", c.answer)
		if r := h.read("conn3x_windows_certificate", state); r.Diagnostics.HasErrors() || winSynced(t, r.NewState) != c.synced {
			t.Errorf("%s: in_sync = %#v, %v", name, r.NewState.GetAttr("in_sync"), r.Diagnostics.Err())
		}
	}
	if got := h.sent("read_certificate.ps1"); got[0]["thumbprint"] != "AB12" || got[0]["store"] != "My" {
		t.Errorf("read sent %v", got[0])
	}
	h.on("read_certificate.ps1", 3)
	if r := h.read("conn3x_windows_certificate", state); !r.Diagnostics.HasErrors() {
		t.Error("a malformed refresh reported no error")
	}

	// Removing it drops the certificate by thumbprint, with no password.
	if r := h.destroy("conn3x_windows_certificate", state); r.Diagnostics.HasErrors() {
		t.Fatal(r.Diagnostics.Err())
	}
	if got := h.sent("apply_certificate.ps1"); len(got) != 2 || got[1]["drop"] != true || got[1]["thumbprint"] != "AB12" || got[1]["password"] != "" {
		t.Errorf("delete sent %v", got)
	}
}

// The password never shows in an error, even one the host echoes it in.
func TestWinCertErrorsHidePassword(t *testing.T) {
	h := newWinFakeHost(t)
	h.fail("apply_certificate.ps1", "bad password s3cret for web.pfx")
	cfg := h.step("conn3x_windows_certificate", map[string]cty.Value{"path": cty.StringVal(`C:\certs\web.pfx`), "store_name": cty.StringVal("My"), "password_wo": cty.StringVal("s3cret")})
	r := h.update("conn3x_windows_certificate", cty.NullVal(cfg.Type()), cfg)
	if !r.Diagnostics.HasErrors() || strings.Contains(r.Diagnostics.Err().Error(), "s3cret") || !strings.Contains(r.Diagnostics.Err().Error(), "windows_certificate: bad password") {
		t.Errorf("error: %v", r.Diagnostics.Err())
	}

	// Write-only, so a config without it can't import a PFX.
	planned := h.plan("conn3x_windows_certificate", cty.NullVal(cfg.Type()), cfg).PlannedState
	vals := cfg.AsValueMap()
	vals["password_wo"] = cty.NullVal(cty.String)
	r = resourceTypes["conn3x_windows_certificate"].apply(ctx, providers.ApplyResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), PlannedState: planned, Config: cty.ObjectVal(vals)})
	if !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "password_wo didn't reach the apply") || len(h.sent("apply_certificate.ps1")) != 1 {
		t.Errorf("no password: %v", r.Diagnostics.Err())
	}

	h.on("apply_certificate.ps1", "imported")
	if r := h.update("conn3x_windows_certificate", cty.NullVal(cfg.Type()), cfg); !r.Diagnostics.HasErrors() {
		t.Error("a malformed answer applied")
	}
}

func TestWinCertAbsent(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("apply_certificate.ps1", map[string]any{})
	cfg := h.step("conn3x_windows_certificate", map[string]cty.Value{"path": cty.StringVal(`C:\certs\ca.cer`), "store_name": cty.StringVal("Root"), "store_location": cty.StringVal("CurrentUser"), "state": cty.StringVal("absent")})
	state := h.create("conn3x_windows_certificate", cfg)
	if !state.GetAttr("thumbprint").IsNull() || !state.GetAttr("file_sha256").IsNull() {
		t.Errorf("an absent certificate kept %#v", state)
	}
	if got := h.sent("apply_certificate.ps1"); got[0]["drop"] != true || got[0]["pfx"] != false || got[0]["location"] != "CurrentUser" {
		t.Errorf("apply sent %v", got)
	}
	h.on("read_certificate.ps1", map[string]any{"in_store": true})
	if r := h.read("conn3x_windows_certificate", state); winSynced(t, r.NewState) {
		t.Error("a certificate still in the store read as absent")
	}
	// The default, forget, leaves the store alone.
	if r := h.destroy("conn3x_windows_certificate", state); r.Diagnostics.HasErrors() || len(h.applied()) != 1 {
		t.Errorf("forget ran %v: %v", h.applied(), r.Diagnostics.Err())
	}
}

func TestWinCertValidate(t *testing.T) {
	r := resourceTypes["conn3x_windows_certificate"]
	if d := r.validate(objFor(r.schema(), map[string]cty.Value{"path": cty.StringVal(`C:\certs\web.pfx`), "store_name": cty.StringVal("My"), "state": cty.StringVal("absent")})); d.HasErrors() {
		t.Error(d.Err())
	}
	for name, bad := range map[string]map[string]cty.Value{
		"no password": {"path": cty.StringVal(`C:\certs\web.p12`), "store_name": cty.StringVal("My")},
		"extension":   {"path": cty.StringVal(`C:\certs\web.pem`), "store_name": cty.StringVal("My")},
		"location":    {"path": cty.StringVal(`C:\certs\ca.cer`), "store_name": cty.StringVal("Root"), "store_location": cty.StringVal("Machine")},
		"store":       {"path": cty.StringVal(`C:\certs\ca.cer`), "store_name": cty.StringVal("My Store")},
		"state":       {"path": cty.StringVal(`C:\certs\ca.cer`), "store_name": cty.StringVal("Root"), "state": cty.StringVal("installed")},
	} {
		if !r.validate(objFor(r.schema(), bad)).HasErrors() {
			t.Errorf("%s: accepted %v", name, bad)
		}
	}
	// An unknown path waits for apply.
	if d := r.validate(objFor(r.schema(), map[string]cty.Value{"path": cty.UnknownVal(cty.String), "store_name": cty.StringVal("My")})); d.HasErrors() {
		t.Error(d.Err())
	}
}
