// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

const winSvcSHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestWinPackageInstall(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("apply_package.ps1", map[string]any{"restart": true})
	winSvcOnApplied(h, "read_package.ps1", "apply_package.ps1", map[string]any{"installed": false}, map[string]any{"installed": true})
	cfg := h.step("conn3x_windows_package", map[string]cty.Value{
		"product_code": cty.StringVal("{23170f69-40c1-2702-2409-000001000000}"), "url": cty.StringVal("https://example.com/7z.msi"),
		"sha256": cty.StringVal(strings.ToUpper(winSvcSHA)), "properties": cty.MapVal(map[string]cty.Value{"INSTALLDIR": cty.StringVal(`C:\7 "zip"`)}), "max_size_mb": cty.NumberIntVal(10),
	})
	state := h.create("conn3x_windows_package", cfg)
	if !winSynced(t, state) || !state.GetAttr("reboot_required").True() {
		t.Errorf("state = %#v", state)
	}
	got := h.sent("apply_package.ps1")
	// Per machine, quotes doubled the way msiexec reads them.
	if len(got) != 1 || got[0]["present"] != true || got[0]["product_code"] != "{23170F69-40C1-2702-2409-000001000000}" || got[0]["sha256"] != winSvcSHA ||
		got[0]["properties"] != `ALLUSERS="1" INSTALLDIR="C:\7 ""zip"""` || got[0]["max_bytes"] != float64(10<<20) {
		t.Fatalf("apply sent %v", got)
	}
	if got := h.sent("read_package.ps1"); got[0]["code"] != "{23170F69-40C1-2702-2409-000001000000}" {
		t.Errorf("read sent %v", got[0])
	}

	// Already installed: msiexec doesn't run, and there's no reboot to want.
	again := h.create("conn3x_windows_package", cfg)
	if n := len(h.sent("apply_package.ps1")); n != 1 || again.GetAttr("reboot_required").True() {
		t.Errorf("an installed package ran msiexec %d times: %#v", n, again)
	}
	h.on("read_package.ps1", map[string]any{"installed": false})
	if r := h.read("conn3x_windows_package", state); winSynced(t, r.NewState) {
		t.Error("an uninstalled package read as in sync")
	}
	h.fail("read_package.ps1", "registry unavailable")
	if r := h.read("conn3x_windows_package", state); !r.Diagnostics.HasErrors() {
		t.Error("a failed refresh reported no error")
	}
	// Removing the step leaves the package.
	if r := h.destroy("conn3x_windows_package", state); r.Diagnostics.HasErrors() || len(h.sent("apply_package.ps1")) != 1 {
		t.Errorf("destroy: %v", r.Diagnostics.Err())
	}
}

func TestWinPackageApplyFailures(t *testing.T) {
	h := newWinFakeHost(t)
	code := cty.StringVal("{23170F69-40C1-2702-2409-000001000000}")
	present := h.step("conn3x_windows_package", map[string]cty.Value{"product_code": code, "source": cty.StringVal(`C:\pkgs\7z.msi`), "sha256": cty.StringVal(winSvcSHA)})
	absent := h.step("conn3x_windows_package", map[string]cty.Value{"product_code": code, "state": cty.StringVal("absent")})
	null := cty.NullVal(present.Type())
	h.on("apply_package.ps1", map[string]any{})

	// msiexec succeeding isn't enough: the product code must then be listed.
	h.on("read_package.ps1", map[string]any{"installed": false})
	if r := h.update("conn3x_windows_package", null, present); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "check product_code against the .msi") {
		t.Errorf("unlisted after install: %v", r.Diagnostics.Err())
	}
	h.on("read_package.ps1", map[string]any{"installed": true})
	if r := h.update("conn3x_windows_package", null, absent); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "still listed as installed") {
		t.Errorf("listed after removal: %v", r.Diagnostics.Err())
	}
	if got := h.sent("apply_package.ps1"); len(got) != 2 || got[0]["source"] != `C:\pkgs\7z.msi` || got[1]["present"] != false {
		t.Errorf("apply sent %v", got)
	}
	h.fail("apply_package.ps1", "msiexec exited 1603")
	if r := h.update("conn3x_windows_package", null, absent); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "windows_package: {23170F69-40C1-2702-2409-000001000000}: msiexec exited 1603") {
		t.Errorf("a host error: %v", r.Diagnostics.Err())
	}
	h.on("apply_package.ps1", "done")
	if r := h.update("conn3x_windows_package", null, absent); !r.Diagnostics.HasErrors() {
		t.Error("a malformed answer applied")
	}
	h.on("read_package.ps1", []any{})
	if r := h.update("conn3x_windows_package", null, absent); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "wasn't valid") {
		t.Errorf("a malformed read: %v", r.Diagnostics.Err())
	}
	// Refused settings never reach the host.
	n := len(h.sent("read_package.ps1"))
	for _, bad := range []cty.Value{
		h.step("conn3x_windows_package", map[string]cty.Value{"product_code": code, "url": cty.StringVal("http://example.com/7z.msi"), "sha256": cty.StringVal(winSvcSHA)}),
		h.step("conn3x_windows_package", map[string]cty.Value{"product_code": code, "source": cty.StringVal(`C:\7z.msi`), "sha256": cty.StringVal(winSvcSHA), "timeout": cty.StringVal("soon")}),
		h.step("conn3x_windows_package", map[string]cty.Value{"product_code": code, "source": cty.StringVal(`C:\7z.msi`), "sha256": cty.StringVal(winSvcSHA), "properties": cty.MapVal(map[string]cty.Value{"TRANSFORMS": cty.StringVal("x.mst")})}),
	} {
		if r := h.update("conn3x_windows_package", null, bad); !r.Diagnostics.HasErrors() {
			t.Errorf("applied %#v", bad)
		}
	}
	if len(h.sent("read_package.ps1")) != n {
		t.Error("a refused package reached the host")
	}
}
