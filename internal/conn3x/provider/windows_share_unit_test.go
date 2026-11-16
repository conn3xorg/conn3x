// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

var winSvcSIDs = map[string]any{`BUILTIN\Administrators`: "S-1-5-32-544", `CONTOSO\Finance`: "S-1-5-21-9-1001"}

func TestWinShareLifecycle(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("apply_share.ps1", nil)
	h.on("read_share.ps1", map[string]any{"exists": false, "sids": winSvcSIDs})
	cfg := h.step("conn3x_windows_share", map[string]cty.Value{
		"name": cty.StringVal("Finance"), "path": cty.StringVal(`D:\Shares\Finance`), "description": cty.StringVal("Ledgers"),
		"full_access": winSvcList(`BUILTIN\Administrators`), "change_access": winSvcList(`CONTOSO\Finance`), "read_access": winSvcList(`CONTOSO\Finance`),
	})
	state := h.create("conn3x_windows_share", cfg)
	if !winSynced(t, state) || state.GetAttr("on_remove").AsString() != "delete" {
		t.Errorf("state = %#v", state)
	}
	// A new share's Everyone Read goes; the stronger right wins for an
	// account listed twice.
	got := h.sent("apply_share.ps1")
	if len(got) != 1 || got[0]["description"] != "Ledgers" || got[0]["path"] != `D:\Shares\Finance` {
		t.Fatalf("apply sent %v", got)
	}
	grants, _ := got[0]["grant"].([]any)
	if len(grants) != 2 || grants[0].(map[string]any)["right"] != "Change" || grants[1].(map[string]any)["right"] != "Full" {
		t.Errorf("grants %v", got[0]["grant"])
	}
	if r, _ := got[0]["revoke"].([]any); len(r) != 1 || r[0] != "Everyone" {
		t.Errorf("revokes %v", got[0]["revoke"])
	}
	if a, _ := h.sent("read_share.ps1")[0]["accounts"].([]any); len(a) != 3 {
		t.Errorf("read asked about %v", a)
	}

	// Accounts compare by SID; a Deny entry is left alone.
	access := []any{
		map[string]any{"account": "Administrators", "sid": "S-1-5-32-544", "right": "Full", "type": "Allow"},
		map[string]any{"account": `CONTOSO\finance`, "sid": "S-1-5-21-9-1001", "right": "Change", "type": "Allow"},
		map[string]any{"account": "Guest", "sid": "S-1-5-21-9-501", "right": "Full", "type": "Deny"},
	}
	h.on("read_share.ps1", map[string]any{"exists": true, "path": `d:\shares\finance\`, "description": "Ledgers", "access": access, "sids": winSvcSIDs})
	if r := h.read("conn3x_windows_share", state); !winSynced(t, r.NewState) {
		t.Error("the same share read as drift")
	}
	h.on("read_share.ps1", map[string]any{"exists": true, "path": `D:\Shares\Finance`, "description": "Ledgers", "access": access[0], "sids": winSvcSIDs})
	if r := h.read("conn3x_windows_share", state); winSynced(t, r.NewState) {
		t.Error("a missing grant read as in sync")
	}
	// An account the host can't resolve can't be compared: a warning, and drift.
	h.on("read_share.ps1", map[string]any{"exists": true, "path": `D:\Shares\Finance`, "description": "Ledgers", "sids": map[string]any{}})
	r := h.read("conn3x_windows_share", state)
	if winSynced(t, r.NewState) || len(r.Diagnostics) != 1 || !strings.Contains(r.Diagnostics[0].Description().Summary, "isn't one this host knows") {
		t.Errorf("unresolved account: %v", r.Diagnostics)
	}
	h.on("read_share.ps1", map[string]any{"exists": true, "access": 7})
	if r := h.read("conn3x_windows_share", state); !r.Diagnostics.HasErrors() {
		t.Error("a malformed refresh reported no error")
	}

	if r := h.destroy("conn3x_windows_share", state); r.Diagnostics.HasErrors() {
		t.Fatal(r.Diagnostics.Err())
	}
	if got := h.sent("apply_share.ps1"); len(got) != 2 || got[1]["drop"] != true || got[1]["name"] != "Finance" {
		t.Errorf("remove sent %v", got)
	}
}

// A share's folder can't change in place.
func TestWinShareRefusesAnotherFolder(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("read_share.ps1", map[string]any{"exists": true, "path": `E:\Other`})
	cfg := h.step("conn3x_windows_share", map[string]cty.Value{"name": cty.StringVal("Finance"), "path": cty.StringVal(`D:\Shares\Finance`)})
	r := h.update("conn3x_windows_share", cty.NullVal(cfg.Type()), cfg)
	if !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), `share Finance is E:\Other`) || len(h.applied()) != 0 {
		t.Errorf("another folder: %v %v", r.Diagnostics.Err(), h.applied())
	}
	r2 := resourceTypes["conn3x_windows_share"]
	for _, bad := range []map[string]cty.Value{
		{"name": cty.StringVal("C$"), "path": cty.StringVal(`C:\`)},
		{"name": cty.StringVal("a/b"), "path": cty.StringVal(`C:\x`)},
		{"name": cty.StringVal("x"), "path": cty.StringVal(`\\srv\x`)},
		{"name": cty.StringVal("x"), "path": cty.StringVal(`C:\x`), "on_remove": cty.StringVal("keep")},
	} {
		if !r2.validate(objFor(r2.schema(), bad)).HasErrors() {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestWinDNSRecordLifecycle(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("apply_dns_record.ps1", nil)
	h.on("read_dns_record.ps1", map[string]any{"zone": true, "values": []any{"10.0.0.5", "10.0.0.9"}, "ttl": 600})
	cfg := h.step("conn3x_windows_dns_record", map[string]cty.Value{
		"zone": cty.StringVal("corp.example.com"), "name": cty.StringVal("www"), "type": cty.StringVal("A"), "values": winSvcList("10.0.0.5", "10.0.0.6"), "on_remove": cty.StringVal("delete"),
	})
	state := h.create("conn3x_windows_dns_record", cfg)
	got := h.sent("apply_dns_record.ps1")
	// The value both have stays, and gets the default TTL in place.
	if len(got) != 1 || got[0]["ttl"] != float64(3600) || got[0]["set_ttl"] != true || got[0]["add_values"].([]any)[0] != "10.0.0.6" || got[0]["remove_values"].([]any)[0] != "10.0.0.9" {
		t.Fatalf("apply sent %v", got)
	}
	if r := h.read("conn3x_windows_dns_record", state); winSynced(t, r.NewState) {
		t.Error("other values read as in sync")
	}
	// PowerShell sends a list of one as the one value.
	h.on("read_dns_record.ps1", map[string]any{"zone": true, "values": "10.0.0.5", "ttl": 3600})
	one := h.step("conn3x_windows_dns_record", map[string]cty.Value{"zone": cty.StringVal("corp.example.com"), "name": cty.StringVal("www"), "type": cty.StringVal("A"), "values": winSvcList("10.0.0.5")})
	if r := h.read("conn3x_windows_dns_record", one); !winSynced(t, r.NewState) {
		t.Error("a single value read as drift")
	}
	h.on("read_dns_record.ps1", map[string]any{"zone": true, "values": 5})
	if r := h.read("conn3x_windows_dns_record", state); !r.Diagnostics.HasErrors() {
		t.Error("a malformed refresh reported no error")
	}

	// Removing it removes every value the server has, by its own spelling.
	h.on("read_dns_record.ps1", map[string]any{"zone": true, "values": []any{"10.0.0.5", "10.0.0.6"}, "ttl": 3600})
	if r := h.destroy("conn3x_windows_dns_record", state); r.Diagnostics.HasErrors() {
		t.Fatal(r.Diagnostics.Err())
	}
	if got := h.sent("apply_dns_record.ps1"); len(got) != 2 || len(got[1]["remove_values"].([]any)) != 2 || len(got[1]["add_values"].([]any)) != 0 {
		t.Errorf("remove sent %v", got)
	}
	// Nothing there: nothing to remove.
	h.on("read_dns_record.ps1", map[string]any{"zone": true})
	if r := h.destroy("conn3x_windows_dns_record", state); r.Diagnostics.HasErrors() || len(h.applied()) != 2 {
		t.Errorf("empty remove ran %v: %v", h.applied(), r.Diagnostics.Err())
	}
}

func TestWinDNSRecordNoZone(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("read_dns_record.ps1", map[string]any{"zone": false})
	cfg := h.step("conn3x_windows_dns_record", map[string]cty.Value{"zone": cty.StringVal("corp.example.com"), "name": cty.StringVal("@"), "type": cty.StringVal("TXT"), "values": winSvcList("v=spf1 -all")})
	r := h.update("conn3x_windows_dns_record", cty.NullVal(cfg.Type()), cfg)
	if !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "no DNS zone corp.example.com") {
		t.Errorf("no zone: %v", r.Diagnostics.Err())
	}
	if r := h.read("conn3x_windows_dns_record", cfg); winSynced(t, r.NewState) {
		t.Error("a missing zone read as in sync")
	}
	rt := resourceTypes["conn3x_windows_dns_record"]
	for _, bad := range []map[string]cty.Value{
		{"zone": cty.StringVal("corp"), "name": cty.StringVal("www"), "type": cty.StringVal("CNAME"), "values": winSvcList("a.corp", "b.corp")},
		{"zone": cty.StringVal("corp"), "name": cty.StringVal("www"), "type": cty.StringVal("AAAA"), "values": winSvcList("10.0.0.1")},
		{"zone": cty.StringVal("corp"), "name": cty.StringVal("www"), "type": cty.StringVal("MX"), "values": winSvcList("mail")},
	} {
		if !rt.validate(objFor(rt.schema(), bad)).HasErrors() {
			t.Errorf("accepted %v", bad)
		}
	}
}
