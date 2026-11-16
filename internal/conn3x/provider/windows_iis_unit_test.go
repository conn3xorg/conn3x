// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

// winSvcOnApplied answers script with before until apply has run, and with
// after from then on, as a host that took the change would.
func winSvcOnApplied(h *winFakeHost, script, apply string, before, after any) {
	h.onFunc(script, func(map[string]any) (any, string) {
		if len(h.sent(apply)) > 0 {
			return after, ""
		}
		return before, ""
	})
}

func winSvcPool(state, identity string) map[string]any {
	return map[string]any{"installed": true, "exists": true, "state": state, "auto_start": state == "Started", "runtime": "v4.0", "pipeline": "Integrated", "identity": identity}
}

func TestWinAppPoolLifecycle(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("apply_iis_app_pool.ps1", nil)
	h.on("apply_iis_app_pool_remove.ps1", nil)
	winSvcOnApplied(h, "read_iis_app_pool.ps1", "apply_iis_app_pool.ps1", map[string]any{"installed": true}, winSvcPool("Started", "ApplicationPoolIdentity"))
	cfg := h.step("conn3x_windows_iis_app_pool", map[string]cty.Value{"name": cty.StringVal("shop")})
	state := h.create("conn3x_windows_iis_app_pool", cfg)
	if !winSynced(t, state) || state.GetAttr("on_remove").AsString() != "delete" {
		t.Errorf("state = %#v", state)
	}
	got := h.sent("apply_iis_app_pool.ps1")
	if len(got) != 1 || got[0]["name"] != "shop" || got[0]["started"] != true || got[0]["runtime"] != "v4.0" || got[0]["pipeline"] != "Integrated" || got[0]["identity"] != "ApplicationPoolIdentity" {
		t.Fatalf("apply sent %v", got)
	}

	// IIS names identities without case; another identity is drift.
	h.on("read_iis_app_pool.ps1", winSvcPool("Started", "applicationpoolidentity"))
	if r := h.read("conn3x_windows_iis_app_pool", state); !winSynced(t, r.NewState) {
		t.Error("the same pool read as drift")
	}
	h.on("read_iis_app_pool.ps1", winSvcPool("Started", "NetworkService"))
	if r := h.read("conn3x_windows_iis_app_pool", state); winSynced(t, r.NewState) {
		t.Error("another identity read as in sync")
	}
	// Already as configured, an apply changes nothing.
	h.on("read_iis_app_pool.ps1", winSvcPool("Started", "ApplicationPoolIdentity"))
	h.create("conn3x_windows_iis_app_pool", cfg)
	if n := len(h.sent("apply_iis_app_pool.ps1")); n != 1 {
		t.Errorf("a matching pool was set %d times", n)
	}

	if r := h.destroy("conn3x_windows_iis_app_pool", state); r.Diagnostics.HasErrors() {
		t.Fatal(r.Diagnostics.Err())
	}
	if got := h.sent("apply_iis_app_pool_remove.ps1"); len(got) != 1 || got[0]["name"] != "shop" {
		t.Errorf("remove sent %v", got)
	}
}

func TestWinAppPoolApplyFailures(t *testing.T) {
	h := newWinFakeHost(t)
	cfg := h.step("conn3x_windows_iis_app_pool", map[string]cty.Value{"name": cty.StringVal("shop"), "state": cty.StringVal("stopped")})
	null := cty.NullVal(cfg.Type())

	// A pool that a set leaves different is an error, not a quiet success.
	h.on("apply_iis_app_pool.ps1", nil)
	h.on("read_iis_app_pool.ps1", winSvcPool("Started", "ApplicationPoolIdentity"))
	r := h.update("conn3x_windows_iis_app_pool", null, cfg)
	if !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "doesn't match what was set") {
		t.Errorf("a set that didn't take: %v", r.Diagnostics.Err())
	}
	if got := h.sent("apply_iis_app_pool.ps1"); got[0]["started"] != false {
		t.Errorf("stopped sent %v", got)
	}
	h.fail("apply_iis_app_pool.ps1", "IIS isn't installed")
	if r := h.update("conn3x_windows_iis_app_pool", null, cfg); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "pool shop: IIS isn't installed") {
		t.Errorf("a host error: %v", r.Diagnostics.Err())
	}
	h.on("read_iis_app_pool.ps1", []any{1})
	if r := h.update("conn3x_windows_iis_app_pool", null, cfg); !r.Diagnostics.HasErrors() {
		t.Error("a malformed read applied")
	}
	if r := h.read("conn3x_windows_iis_app_pool", cfg); !r.Diagnostics.HasErrors() {
		t.Error("a malformed refresh reported no error")
	}
}

func winSvcSite(h *winFakeHost, attrs map[string]cty.Value, bindings ...map[string]cty.Value) cty.Value {
	vals := siteObj(resourceTypes["conn3x_windows_iis_site"], attrs, bindings...).AsValueMap()
	vals["ssh"] = h.conn
	return cty.ObjectVal(vals)
}

func TestWinSiteLifecycle(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("apply_iis_site.ps1", nil)
	h.on("apply_iis_site_remove.ps1", nil)
	site := map[string]any{"installed": true, "exists": true, "state": "Started", "auto_start": true, "physical_path": `C:/sites/shop/`, "app_pool": "SHOP",
		"bindings": []any{map[string]any{"protocol": "http", "information": "*:80:shop.example.com"}, map[string]any{"protocol": "HTTP", "information": "10.0.0.5:8080:"}}}
	winSvcOnApplied(h, "read_iis_site.ps1", "apply_iis_site.ps1", map[string]any{"installed": true}, site)
	cfg := winSvcSite(h, map[string]cty.Value{"name": cty.StringVal("shop"), "physical_path": cty.StringVal(`C:\sites\shop`), "app_pool": cty.StringVal("shop")},
		map[string]cty.Value{"port": cty.NumberIntVal(80), "host_header": cty.StringVal("Shop.example.com")},
		map[string]cty.Value{"port": cty.NumberIntVal(8080), "ip": cty.StringVal("::ffff:10.0.0.5")})
	state := h.create("conn3x_windows_iis_site", cfg)
	if !winSynced(t, state) {
		t.Error("a created site isn't in sync")
	}
	got := h.sent("apply_iis_site.ps1")
	if len(got) != 1 || got[0]["physical_path"] != `C:\sites\shop` || got[0]["app_pool"] != "shop" || got[0]["started"] != true {
		t.Fatalf("apply sent %v", got)
	}
	// Bindings go as IIS writes them: host names lower case, mapped v4 plain.
	bs, _ := got[0]["bindings"].([]any)
	if len(bs) != 2 || bs[0].(map[string]any)["information"] != "*:80:shop.example.com" || bs[1].(map[string]any)["information"] != "10.0.0.5:8080:" {
		t.Errorf("bindings sent %v", bs)
	}

	// A binding added by hand is drift.
	extra := map[string]any{}
	for k, v := range site {
		extra[k] = v
	}
	extra["bindings"] = append(site["bindings"].([]any), map[string]any{"protocol": "http", "information": "*:81:"})
	h.on("read_iis_site.ps1", extra)
	if r := h.read("conn3x_windows_iis_site", state); winSynced(t, r.NewState) {
		t.Error("an extra binding read as in sync")
	}
	h.fail("read_iis_site.ps1", "the WebAdministration module isn't there")
	if r := h.read("conn3x_windows_iis_site", state); !r.Diagnostics.HasErrors() {
		t.Error("a failed refresh reported no error")
	}

	if r := h.destroy("conn3x_windows_iis_site", state); r.Diagnostics.HasErrors() {
		t.Fatal(r.Diagnostics.Err())
	}
	if got := h.sent("apply_iis_site_remove.ps1"); len(got) != 1 || got[0]["name"] != "shop" {
		t.Errorf("remove sent %v", got)
	}
}

// With no app_pool, a new site gets IIS's default: the script gets null.
func TestWinSiteLeavesPoolAlone(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("read_iis_site.ps1", map[string]any{"installed": true})
	h.on("apply_iis_site.ps1", nil)
	cfg := winSvcSite(h, map[string]cty.Value{"name": cty.StringVal("shop"), "physical_path": cty.StringVal(`C:\sites\shop`), "on_remove": cty.StringVal("forget")},
		map[string]cty.Value{"port": cty.NumberIntVal(80)})
	r := h.update("conn3x_windows_iis_site", cty.NullVal(cfg.Type()), cfg)
	if !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "site shop doesn't match") {
		t.Errorf("a set that didn't take: %v", r.Diagnostics.Err())
	}
	if got := h.sent("apply_iis_site.ps1"); len(got) != 1 || got[0]["app_pool"] != nil {
		t.Errorf("apply sent %v", got)
	}
	h.fail("apply_iis_site.ps1", "port in use")
	if r := h.update("conn3x_windows_iis_site", cty.NullVal(cfg.Type()), cfg); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "site shop: port in use") {
		t.Errorf("a host error: %v", r.Diagnostics.Err())
	}
	// forget leaves the site.
	vals := cfg.AsValueMap()
	vals["in_sync"] = cty.True
	if r := h.destroy("conn3x_windows_iis_site", cty.ObjectVal(vals)); r.Diagnostics.HasErrors() || len(h.sent("apply_iis_site_remove.ps1")) != 0 {
		t.Errorf("forget removed the site: %v", r.Diagnostics.Err())
	}
}
