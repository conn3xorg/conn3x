// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// winADSeq answers runs of script with answers in turn, then the last one
// for good.
func winADSeq(h *winFakeHost, script string, answers ...any) {
	var mu sync.Mutex
	n := 0
	h.onFunc(script, func(map[string]any) (any, string) {
		mu.Lock()
		defer mu.Unlock()
		a := answers[min(n, len(answers)-1)]
		n++
		return a, ""
	})
}

// winADAs logs in as user instead.
func winADAs(v cty.Value, user string) cty.Value {
	vals := v.AsValueMap()
	conn := vals["ssh"].AsValueMap()
	conn["user"] = cty.StringVal(user)
	vals["ssh"] = cty.ObjectVal(conn)
	return cty.ObjectVal(vals)
}

// winADFacts is a workgroup server named DC1, about to be promoted.
func winADFacts(h *winFakeHost) {
	h.on("read_facts.ps1", map[string]any{"version": "10.0.20348", "build": "20348", "product_type": 3, "arch": "AMD64", "hostname": "DC1", "domain": "WORKGROUP", "edition": "ServerStandard", "installation_type": "Server", "powershell": "5.1"})
}

// What read_ad_forest.ps1 answers for a host in each state.
var (
	winADWorkgroup = map[string]any{"role": 2, "domain": "WORKGROUP"}
	winADForestDC  = map[string]any{"role": 5, "domain": "lab.example.com", "root_dn": "DC=lab,DC=example,DC=com", "part": true}
	winADPending   = map[string]any{"role": 2, "domain": "WORKGROUP", "root_dn": "DC=lab,DC=example,DC=com", "marker": true}
	winADMember    = map[string]any{"role": 3, "domain": "lab.example.com", "part": true}
)

func TestWinForestPromotes(t *testing.T) {
	h := newWinFakeHost(t)
	winADFacts(h)
	winADSeq(h, "read_ad_forest.ps1", winADWorkgroup, winADPending)
	h.on("apply_ad_forest.ps1", map[string]any{"restart": true})
	cfg := h.step("conn3x_windows_ad_forest", map[string]cty.Value{
		"domain_name": cty.StringVal("lab.example.com"), "netbios_name": cty.StringVal("LAB"), "database_path": cty.StringVal(`C:/NTDS/`),
		"safe_mode_password_wo": cty.StringVal("dsrm-s3cret"),
	})
	state := h.create("conn3x_windows_ad_forest", cfg)
	if !winSynced(t, state) || !state.GetAttr("reboot_required").True() || !state.GetAttr("safe_mode_password_wo").IsNull() {
		t.Fatalf("state %#v", state)
	}
	got := h.sent("apply_ad_forest.ps1")
	if len(got) != 1 || got[0]["domain_name"] != "lab.example.com" || got[0]["netbios_name"] != "LAB" || got[0]["password"] != "dsrm-s3cret" || got[0]["database_path"] != `C:\NTDS` || got[0]["log_path"] != "" {
		t.Errorf("apply sent %v", got)
	}

	// Refresh: still pending, then promoted, then a different forest.
	for _, c := range []struct {
		answer map[string]any
		want   bool
	}{{winADPending, true}, {winADForestDC, true}, {winADWorkgroup, false}} {
		h.on("read_ad_forest.ps1", c.answer)
		if r := h.read("conn3x_windows_ad_forest", state); r.Diagnostics.HasErrors() || winSynced(t, r.NewState) != c.want {
			t.Errorf("%v: %v %#v", c.answer, r.Diagnostics.Err(), r.NewState.GetAttr("in_sync"))
		}
	}
	h.on("read_ad_forest.ps1", []int{1})
	if r := h.read("conn3x_windows_ad_forest", state); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "wasn't valid") {
		t.Errorf("a malformed answer: %v", r.Diagnostics.Err())
	}
}

// A forest already there is left as it is, and only says whether a reboot
// is still wanted.
func TestWinForestAlreadyThere(t *testing.T) {
	h := newWinFakeHost(t)
	cfg := h.step("conn3x_windows_ad_forest", map[string]cty.Value{"domain_name": cty.StringVal("LAB.example.com")})
	for _, c := range []struct {
		answer  map[string]any
		restart bool
	}{{winADForestDC, false}, {winADPending, true}} {
		h.on("read_ad_forest.ps1", c.answer)
		state := h.create("conn3x_windows_ad_forest", cfg)
		if !winSynced(t, state) || state.GetAttr("reboot_required").True() != c.restart {
			t.Errorf("%v: %#v", c.answer, state)
		}
	}
	if a := h.applied(); len(a) != 0 {
		t.Errorf("ran %v", a)
	}
}

func TestWinForestRefusals(t *testing.T) {
	pw := map[string]cty.Value{"domain_name": cty.StringVal("lab.example.com"), "safe_mode_password_wo": cty.StringVal("pw")}
	for name, c := range map[string]struct {
		forest  any
		user    string
		attrs   map[string]cty.Value
		apply   func(h *winFakeHost)
		wantErr string
	}{
		"another forest":  {forest: map[string]any{"role": 5, "domain": "other.test", "root_dn": "DC=other,DC=test"}, attrs: pw, wantErr: "already a domain controller in other.test"},
		"a member":        {forest: winADMember, attrs: pw, wantErr: "is a member of lab.example.com"},
		"local login":     {forest: winADWorkgroup, user: `dc1\admin`, attrs: pw, wantErr: "names a local account"},
		"unchecked login": {forest: winADWorkgroup, user: `OTHER\admin`, attrs: pw, wantErr: "Set netbios_name"},
		"no password":     {forest: winADWorkgroup, attrs: map[string]cty.Value{"domain_name": cty.StringVal("lab.example.com")}, wantErr: "safe_mode_password_wo is needed"},
		"host refuses": {forest: winADWorkgroup, attrs: pw, wantErr: "making forest lab.example.com: the name LAB is taken",
			apply: func(h *winFakeHost) { h.fail("apply_ad_forest.ps1", "the name LAB is taken") }},
		"no result": {forest: winADWorkgroup, attrs: pw, wantErr: "reading the result for forest",
			apply: func(h *winFakeHost) { h.on("apply_ad_forest.ps1", "done") }},
		"didn't take": {forest: winADWorkgroup, attrs: pw, wantErr: "doesn't show forest",
			apply: func(h *winFakeHost) { h.on("apply_ad_forest.ps1", map[string]any{"restart": true}) }},
	} {
		t.Run(name, func(t *testing.T) {
			h := newWinFakeHost(t)
			winADFacts(h)
			h.on("read_ad_forest.ps1", c.forest)
			if c.apply != nil {
				c.apply(h)
			}
			cfg := h.step("conn3x_windows_ad_forest", c.attrs)
			if c.user != "" {
				cfg = winADAs(cfg, c.user)
			}
			r := h.update("conn3x_windows_ad_forest", cty.NullVal(cfg.Type()), cfg)
			if !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), c.wantErr) {
				t.Errorf("got %v, want %q", r.Diagnostics.Err(), c.wantErr)
			}
		})
	}
}

// The host's own error never carries the password back.
func TestWinADPasswordsScrubbed(t *testing.T) {
	h := newWinFakeHost(t)
	winADFacts(h)
	h.on("read_ad_forest.ps1", winADWorkgroup)
	h.fail("apply_ad_forest.ps1", "refused dsrm-s3cret")
	cfg := h.step("conn3x_windows_ad_forest", map[string]cty.Value{"domain_name": cty.StringVal("lab.example.com"), "safe_mode_password_wo": cty.StringVal("dsrm-s3cret")})
	r := h.update("conn3x_windows_ad_forest", cty.NullVal(cfg.Type()), cfg)
	if !r.Diagnostics.HasErrors() || strings.Contains(r.Diagnostics.Err().Error(), "dsrm-s3cret") {
		t.Errorf("got %v", r.Diagnostics.Err())
	}
	h.fail("apply_domain_membership.ps1", "bad join-s3cret")
	cfg = h.step("conn3x_windows_domain_membership", map[string]cty.Value{"domain": cty.StringVal("lab.example.com"), "username": cty.StringVal(`LAB\joiner`), "password_wo": cty.StringVal("join-s3cret")})
	r = h.update("conn3x_windows_domain_membership", cty.NullVal(cfg.Type()), cfg)
	if !r.Diagnostics.HasErrors() || strings.Contains(r.Diagnostics.Err().Error(), "join-s3cret") {
		t.Errorf("got %v", r.Diagnostics.Err())
	}
}

func TestWinMembershipJoins(t *testing.T) {
	h := newWinFakeHost(t)
	winADSeq(h, "read_ad_forest.ps1", winADWorkgroup, winADMember)
	h.on("apply_domain_membership.ps1", map[string]any{"restart": true})
	cfg := h.step("conn3x_windows_domain_membership", map[string]cty.Value{
		"domain": cty.StringVal("lab.example.com"), "ou": cty.StringVal("OU=Servers,DC=lab,DC=example,DC=com"),
		"username": cty.StringVal(`LAB\joiner`), "password_wo": cty.StringVal("join-pw"), "timeout": cty.StringVal("2m"),
	})
	state := h.create("conn3x_windows_domain_membership", cfg)
	if !winSynced(t, state) || !state.GetAttr("reboot_required").True() || !state.GetAttr("password_wo").IsNull() {
		t.Fatalf("state %#v", state)
	}
	got := h.sent("apply_domain_membership.ps1")
	if len(got) != 1 || got[0]["domain"] != "lab.example.com" || got[0]["ou"] != "OU=Servers,DC=lab,DC=example,DC=com" || got[0]["username"] != `LAB\joiner` || got[0]["password"] != "join-pw" {
		t.Errorf("apply sent %v", got)
	}
	if r := h.read("conn3x_windows_domain_membership", state); !winSynced(t, r.NewState) {
		t.Error("a joined host read as out of sync")
	}

	// Joined and not yet rebooted reads as joined: the reboot still wanted
	// carries over from state.
	r := h.update("conn3x_windows_domain_membership", state, cfg)
	if r.Diagnostics.HasErrors() || !r.NewState.GetAttr("reboot_required").True() || len(h.sent("apply_domain_membership.ps1")) != 1 {
		t.Errorf("rejoined, or lost reboot_required: %v %#v", r.Diagnostics.Err(), r.NewState)
	}

	h.on("read_ad_forest.ps1", map[string]any{"role": 3, "domain": "other.test", "part": true})
	if r := h.read("conn3x_windows_domain_membership", state); winSynced(t, r.NewState) {
		t.Error("another domain read as in sync")
	}
	r = h.update("conn3x_windows_domain_membership", cty.NullVal(cfg.Type()), cfg)
	if !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "already in other.test") {
		t.Errorf("another domain: %v", r.Diagnostics.Err())
	}
}

func TestWinMembershipRefusals(t *testing.T) {
	base := map[string]cty.Value{"domain": cty.StringVal("lab.example.com"), "username": cty.StringVal(`LAB\joiner`)}
	h := newWinFakeHost(t)
	h.on("read_ad_forest.ps1", winADWorkgroup)
	cfg := h.step("conn3x_windows_domain_membership", base)
	if r := h.update("conn3x_windows_domain_membership", cty.NullVal(cfg.Type()), cfg); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "password_wo is needed") {
		t.Errorf("no password: %v", r.Diagnostics.Err())
	}
	h.on("apply_domain_membership.ps1", map[string]any{"restart": true})
	vals := cfg.AsValueMap()
	vals["password_wo"] = cty.StringVal("pw")
	cfg = cty.ObjectVal(vals)
	if r := h.update("conn3x_windows_domain_membership", cty.NullVal(cfg.Type()), cfg); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "Add-Computer reported success") {
		t.Errorf("didn't take: %v", r.Diagnostics.Err())
	}
	h.on("apply_domain_membership.ps1", []string{})
	if r := h.update("conn3x_windows_domain_membership", cty.NullVal(cfg.Type()), cfg); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "reading the result for joining") {
		t.Errorf("no result: %v", r.Diagnostics.Err())
	}
	h.fail("read_ad_forest.ps1", "WMI is broken")
	if r := h.update("conn3x_windows_domain_membership", cty.NullVal(cfg.Type()), cfg); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "WMI is broken") {
		t.Errorf("read fails: %v", r.Diagnostics.Err())
	}
	if r := h.read("conn3x_windows_domain_membership", cfg); !r.Diagnostics.HasErrors() {
		t.Error("refresh: a failed read reported no error")
	}
}

func TestWinDCPromotes(t *testing.T) {
	h := newWinFakeHost(t)
	winADFacts(h)
	winADSeq(h, "read_ad_forest.ps1", winADMember, map[string]any{"role": 3, "domain": "lab.example.com", "part": true, "root_dn": "DC=lab,DC=example,DC=com", "marker": true})
	h.on("apply_ad_domain_controller.ps1", map[string]any{"restart": true})
	cfg := h.step("conn3x_windows_ad_domain_controller", map[string]cty.Value{
		"domain_name": cty.StringVal("lab.example.com"), "username": cty.StringVal(`LAB\admin`), "sysvol_path": cty.StringVal(`D:\SYSVOL\`),
		"password_wo": cty.StringVal("pw"), "safe_mode_password_wo": cty.StringVal("dsrm"),
	})
	state := h.create("conn3x_windows_ad_domain_controller", cfg)
	if !winSynced(t, state) || !state.GetAttr("reboot_required").True() || !state.GetAttr("password_wo").IsNull() || !state.GetAttr("safe_mode_password_wo").IsNull() {
		t.Fatalf("state %#v", state)
	}
	got := h.sent("apply_ad_domain_controller.ps1")
	if len(got) != 1 || got[0]["domain_name"] != "lab.example.com" || got[0]["username"] != `LAB\admin` || got[0]["password"] != "pw" || got[0]["safe_mode_password"] != "dsrm" || got[0]["sysvol_path"] != `D:\SYSVOL` {
		t.Errorf("apply sent %v", got)
	}
	h.on("read_ad_forest.ps1", winADForestDC)
	if r := h.read("conn3x_windows_ad_domain_controller", state); !winSynced(t, r.NewState) {
		t.Error("a DC read as out of sync")
	}
	if r := h.update("conn3x_windows_ad_domain_controller", state, cfg); r.Diagnostics.HasErrors() || r.NewState.GetAttr("reboot_required").True() || len(h.applied()) != 1 {
		t.Errorf("a DC promoted again: %v %v", r.Diagnostics.Err(), h.applied())
	}
}

func TestWinDCRefusals(t *testing.T) {
	both := map[string]cty.Value{"domain_name": cty.StringVal("lab.example.com"), "username": cty.StringVal(`LAB\admin`), "password_wo": cty.StringVal("pw"), "safe_mode_password_wo": cty.StringVal("dsrm")}
	for name, c := range map[string]struct {
		forest  any
		user    string
		attrs   map[string]cty.Value
		apply   any
		wantErr string
	}{
		"another forest":   {forest: map[string]any{"role": 5, "domain": "other.test", "root_dn": "DC=other,DC=test", "part": true}, attrs: both, wantErr: "already a domain controller in other.test"},
		"another domain":   {forest: map[string]any{"role": 3, "domain": "other.test", "part": true}, attrs: both, wantErr: "is a member of other.test"},
		"local login":      {forest: winADMember, user: `DC1\admin`, attrs: both, wantErr: "names a local account"},
		"no passwords":     {forest: winADMember, attrs: map[string]cty.Value{"domain_name": cty.StringVal("lab.example.com"), "username": cty.StringVal(`LAB\admin`), "password_wo": cty.StringVal("pw")}, wantErr: "are needed to promote"},
		"didn't take":      {forest: winADMember, attrs: both, apply: map[string]any{"restart": true}, wantErr: "Install-ADDSDomainController reported success"},
		"malformed result": {forest: winADMember, attrs: both, apply: 7, wantErr: "reading the result for domain controller in lab.example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newWinFakeHost(t)
			winADFacts(h)
			h.on("read_ad_forest.ps1", c.forest)
			if c.apply != nil {
				h.on("apply_ad_domain_controller.ps1", c.apply)
			}
			cfg := h.step("conn3x_windows_ad_domain_controller", c.attrs)
			if c.user != "" {
				cfg = winADAs(cfg, c.user)
			}
			r := h.update("conn3x_windows_ad_domain_controller", cty.NullVal(cfg.Type()), cfg)
			if !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), c.wantErr) {
				t.Errorf("got %v, want %q", r.Diagnostics.Err(), c.wantErr)
			}
		})
	}
}

func TestWinChildDomainPromotes(t *testing.T) {
	for name, c := range map[string]struct {
		attrs         map[string]cty.Value
		label, parent string
	}{
		"child": {map[string]cty.Value{"domain_name": cty.StringVal("emea.lab.example.com"), "username": cty.StringVal("admin@lab.example.com")}, "emea", "lab.example.com"},
		"tree": {map[string]cty.Value{"domain_name": cty.StringVal("apac.example.net"), "domain_type": cty.StringVal("tree"), "parent_domain_name": cty.StringVal("lab.example.com"), "username": cty.StringVal(`lab.example.com\admin`)},
			"apac.example.net", "lab.example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newWinFakeHost(t)
			winADFacts(h)
			domain := c.attrs["domain_name"].AsString()
			// Until the reboot, Windows says workgroup; the marker names the domain.
			pending := map[string]any{"role": 2, "domain": "WORKGROUP", "root_dn": "DC=lab,DC=example,DC=com", "marker": true, "promoted": domain}
			winADSeq(h, "read_ad_forest.ps1", winADWorkgroup, pending)
			h.on("apply_ad_domain.ps1", map[string]any{"restart": true})
			attrs := map[string]cty.Value{"password_wo": cty.StringVal("pw"), "safe_mode_password_wo": cty.StringVal("dsrm")}
			for k, v := range c.attrs {
				attrs[k] = v
			}
			state := h.create("conn3x_windows_ad_domain", h.step("conn3x_windows_ad_domain", attrs))
			if !winSynced(t, state) || !state.GetAttr("reboot_required").True() {
				t.Fatalf("state %#v", state)
			}
			got := h.sent("apply_ad_domain.ps1")
			if len(got) != 1 || got[0]["label"] != c.label || got[0]["parent"] != c.parent || got[0]["tree"] != (name == "tree") || got[0]["password"] != "pw" {
				t.Errorf("apply sent %v", got)
			}
			h.on("read_ad_forest.ps1", map[string]any{"role": 5, "domain": domain, "root_dn": "DC=lab,DC=example,DC=com", "part": true})
			if r := h.read("conn3x_windows_ad_domain", state); !winSynced(t, r.NewState) {
				t.Error("the new domain's DC read as out of sync")
			}
		})
	}
}

func TestWinChildDomainRefusals(t *testing.T) {
	both := map[string]cty.Value{"domain_name": cty.StringVal("emea.lab.example.com"), "username": cty.StringVal("admin@lab.example.com"), "password_wo": cty.StringVal("pw"), "safe_mode_password_wo": cty.StringVal("dsrm")}
	for name, c := range map[string]struct {
		forest  any
		user    string
		attrs   map[string]cty.Value
		apply   func(h *winFakeHost)
		wantErr string
	}{
		"a DC already": {forest: winADForestDC, attrs: both, wantErr: "already a domain controller in lab.example.com"},
		"a member":     {forest: winADMember, attrs: both, wantErr: "is a member of lab.example.com"},
		"local login":  {forest: winADWorkgroup, user: `.\admin`, attrs: both, wantErr: "names a local account"},
		"no passwords": {forest: winADWorkgroup, attrs: map[string]cty.Value{"domain_name": cty.StringVal("emea.lab.example.com"), "username": cty.StringVal("admin@lab.example.com")}, wantErr: "are needed to make domain"},
		"host refuses": {forest: winADWorkgroup, attrs: both, wantErr: "making domain emea.lab.example.com under lab.example.com: no DC for",
			apply: func(h *winFakeHost) { h.fail("apply_ad_domain.ps1", "no DC for lab.example.com") }},
		"didn't take": {forest: winADWorkgroup, attrs: both, wantErr: "Install-ADDSDomain reported success",
			apply: func(h *winFakeHost) { h.on("apply_ad_domain.ps1", map[string]any{"restart": false}) }},
	} {
		t.Run(name, func(t *testing.T) {
			h := newWinFakeHost(t)
			winADFacts(h)
			h.on("read_ad_forest.ps1", c.forest)
			if c.apply != nil {
				c.apply(h)
			}
			cfg := h.step("conn3x_windows_ad_domain", c.attrs)
			if c.user != "" {
				cfg = winADAs(cfg, c.user)
			}
			// Straight to apply: validate refuses .\ before it gets there.
			planned := h.plan("conn3x_windows_ad_domain", cty.NullVal(cfg.Type()), cfg).PlannedState
			r := resourceTypes["conn3x_windows_ad_domain"].apply(context.Background(), providers.ApplyResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), PlannedState: planned, Config: cfg})
			if !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), c.wantErr) {
				t.Errorf("got %v, want %q", r.Diagnostics.Err(), c.wantErr)
			}
		})
	}
}

// What apply checks itself, for a plan that skipped validate, fails before
// anything connects: the ssh block here reaches nothing.
func TestWinPromotionsCheckBeforeConnecting(t *testing.T) {
	for typ, attrs := range map[string]map[string]cty.Value{
		"conn3x_windows_ad_forest":            {"domain_name": cty.StringVal("lab"), "timeout": cty.StringVal("1m")},
		"conn3x_windows_domain_membership":    {"domain": cty.StringVal("lab.example.com"), "username": cty.StringVal("joiner"), "timeout": cty.StringVal("soon")},
		"conn3x_windows_ad_domain_controller": {"domain_name": cty.StringVal("lab.example.com"), "username": cty.StringVal("a"), "timeout": cty.StringVal("soon")},
		"conn3x_windows_ad_domain":            {"domain_name": cty.StringVal("emea.lab.example.com"), "username": cty.StringVal("admin@lab.example.com"), "timeout": cty.StringVal("soon")},
		"conn3x_windows_dns_client":           {"servers": cty.ListVal([]cty.Value{cty.StringVal("dns.example.com")})},
	} {
		r := resourceTypes[typ]
		v := objFor(r.schema(), attrs)
		resp := r.apply(context.Background(), providers.ApplyResourceChangeRequest{PriorState: cty.NullVal(v.Type()), PlannedState: v, Config: v})
		if !resp.Diagnostics.HasErrors() || strings.Contains(resp.Diagnostics.Err().Error(), "203.0.113.10") {
			t.Errorf("%s: %v", typ, resp.Diagnostics.Err())
		}
	}
}

func TestWinDNSClientLifecycle(t *testing.T) {
	h := newWinFakeHost(t)
	old := map[string]any{"found": true, "index": 4, "alias": "Ethernet", "ipv4": []string{"10.0.0.1"}, "ipv6": []string{"fd00::1"}}
	set := map[string]any{"found": true, "index": 4, "alias": "Ethernet", "ipv4": []string{"10.0.0.53", "10.0.0.54"}, "ipv6": []string{"fd00::1"}}
	winADSeq(h, "read_dns_client.ps1", old, set)
	h.on("apply_dns_client.ps1", nil)
	cfg := h.step("conn3x_windows_dns_client", map[string]cty.Value{"interface": cty.StringVal("Ethernet"), "servers": cty.ListVal([]cty.Value{cty.StringVal("10.0.0.53"), cty.StringVal("10.0.0.54")})})
	state := h.create("conn3x_windows_dns_client", cfg)
	if !winSynced(t, state) {
		t.Error("set servers aren't in sync")
	}
	got := h.sent("apply_dns_client.ps1")
	if len(got) != 1 || got[0]["interface"] != "Ethernet" || len(got[0]["servers"].([]any)) != 2 {
		t.Errorf("apply sent %v", got)
	}
	// IPv4 servers alone leave IPv6 out of it.
	if r := h.read("conn3x_windows_dns_client", state); !winSynced(t, r.NewState) {
		t.Error("matching IPv4 servers read as out of sync")
	}
	h.create("conn3x_windows_dns_client", cfg)
	if n := len(h.sent("apply_dns_client.ps1")); n != 1 {
		t.Errorf("servers already set were set again: %d", n)
	}
	// Order counts.
	h.on("read_dns_client.ps1", map[string]any{"found": true, "ipv4": []string{"10.0.0.54", "10.0.0.53"}})
	if r := h.read("conn3x_windows_dns_client", state); winSynced(t, r.NewState) {
		t.Error("servers in another order read as in sync")
	}
	r := h.update("conn3x_windows_dns_client", state, cfg)
	if !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "don't match what was set") {
		t.Errorf("a set that didn't stick: %v", r.Diagnostics.Err())
	}
	h.on("read_dns_client.ps1", map[string]any{"found": false})
	if r := h.read("conn3x_windows_dns_client", state); winSynced(t, r.NewState) {
		t.Error("a missing interface read as in sync")
	}
	h.fail("apply_dns_client.ps1", "no such interface")
	if r := h.update("conn3x_windows_dns_client", state, cfg); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "windows_dns_client: no such interface") {
		t.Errorf("a host error: %v", r.Diagnostics.Err())
	}
	h.on("read_dns_client.ps1", "nope")
	if r := h.read("conn3x_windows_dns_client", state); !r.Diagnostics.HasErrors() {
		t.Error("a malformed answer read without error")
	}
	if r := h.update("conn3x_windows_dns_client", state, cfg); !r.Diagnostics.HasErrors() {
		t.Error("a malformed answer applied without error")
	}
	if r := h.destroy("conn3x_windows_dns_client", state); r.Diagnostics.HasErrors() || !r.NewState.IsNull() {
		t.Errorf("remove: %v", r.Diagnostics.Err())
	}
}
