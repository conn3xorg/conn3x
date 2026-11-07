// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func TestWinDNSClientValidate(t *testing.T) {
	r := resourceTypes["conn3x_windows_dns_client"]
	list := func(s ...string) cty.Value {
		var vs []cty.Value
		for _, x := range s {
			vs = append(vs, cty.StringVal(x))
		}
		return cty.ListVal(vs)
	}
	if d := r.validate(objFor(r.schema(), map[string]cty.Value{"servers": list("10.0.0.4", "2001:db8::4")})); d.HasErrors() {
		t.Fatal(d.Err())
	}
	for name, a := range map[string]map[string]cty.Value{
		"empty":    {"servers": cty.ListValEmpty(cty.String)},
		"name":     {"servers": list("dc1")},
		"wildcard": {"interface": cty.StringVal("Eth*"), "servers": list("10.0.0.4")},
	} {
		if d := r.validate(objFor(r.schema(), a)); !d.HasErrors() {
			t.Errorf("%s: accepted", name)
		}
	}
	// A server known only at apply, such as a DC's address, waits for apply.
	if d := r.validate(objFor(r.schema(), map[string]cty.Value{"servers": cty.ListVal([]cty.Value{cty.UnknownVal(cty.String)})})); d.HasErrors() {
		t.Error(d.Err())
	}
}

func forestCfg(r resourceType, user string, attrs map[string]cty.Value) cty.Value {
	c := objFor(r.schema(), attrs).AsValueMap()
	ssh := c["ssh"].AsValueMap()
	ssh["user"] = cty.StringVal(user)
	c["ssh"] = cty.ObjectVal(ssh)
	return cty.ObjectVal(c)
}

func TestWinForestValidate(t *testing.T) {
	r := resourceTypes["conn3x_windows_ad_forest"]
	ok := map[string]cty.Value{"domain_name": cty.StringVal("lab.example.com"), "safe_mode_password_wo": cty.StringVal("x")}
	withNetBIOS := map[string]cty.Value{"domain_name": cty.StringVal("lab.example.com"), "netbios_name": cty.StringVal("lab"), "safe_mode_password_wo": cty.StringVal("x")}
	for _, c := range []struct {
		user  string
		attrs map[string]cty.Value
	}{{"azadmin", ok}, {`lab.example.com\azadmin`, ok}, {"azadmin@lab.example.com", ok}, {`LAB\azadmin`, withNetBIOS}} {
		if d := r.validate(forestCfg(r, c.user, c.attrs)); d.HasErrors() {
			t.Errorf("%s: %v", c.user, d.Err())
		}
	}
	// .\user is local, whatever the domain.
	if d := r.validate(forestCfg(r, `.\azadmin`, ok)); !d.HasErrors() || !strings.Contains(d.Err().Error(), "local account") {
		t.Errorf(".\\azadmin: %v", d.Err())
	}
	// Without netbios_name, LAB\ may be the host or the domain: apply, which
	// knows the host's name, decides.
	if d := r.validate(forestCfg(r, `LAB\azadmin`, ok)); d.HasErrors() {
		t.Errorf("LAB\\azadmin at validate: %v", d.Err())
	}
	f := windows.Forest{DomainName: "lab.example.com"}
	c := forestCfg(r, `WIN1\azadmin`, ok)
	if why := forestLockout(c, f, "win1"); !strings.Contains(why, "local account") {
		t.Errorf("host-named login: %q", why)
	}
	if why := forestLockout(c, f, "verylonghostname1"); !strings.Contains(why, "Set netbios_name") {
		t.Errorf("unknown prefix at apply: %q", why)
	}
	if why := forestLockout(forestCfg(r, `VERYLONGHOSTNAM\azadmin`, ok), f, "verylonghostname1"); !strings.Contains(why, "local account") {
		t.Errorf("15-character host prefix: %q", why)
	}
	// Adopting a forest that's there needs no password; making one fails at apply without it.
	if d := r.validate(forestCfg(r, "azadmin", map[string]cty.Value{"domain_name": cty.StringVal("lab.example.com")})); d.HasErrors() {
		t.Error(d.Err())
	}
	if d := r.validate(forestCfg(r, `WIN1\azadmin`, withNetBIOS)); !d.HasErrors() || !strings.Contains(d.Err().Error(), "after promotion") {
		t.Errorf("a host-local login was accepted: %v", d.Err())
	}
	for name, a := range map[string]map[string]cty.Value{
		"empty password": {"domain_name": cty.StringVal("lab.example.com"), "safe_mode_password_wo": cty.StringVal("")},
		"single label":   {"domain_name": cty.StringVal("lab"), "safe_mode_password_wo": cty.StringVal("x")},
		"unc path":       {"domain_name": cty.StringVal("lab.test"), "safe_mode_password_wo": cty.StringVal("x"), "database_path": cty.StringVal(`\\s\x`)},
		"timeout":        {"domain_name": cty.StringVal("lab.test"), "safe_mode_password_wo": cty.StringVal("x"), "timeout": cty.StringVal("soon")},
	} {
		if d := r.validate(forestCfg(r, "azadmin", a)); !d.HasErrors() {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The password is in no plan, and a domain name that changes only in case
// is the same forest.
func TestWinForestPlan(t *testing.T) {
	r := resourceTypes["conn3x_windows_ad_forest"]
	c := forestCfg(r, "azadmin", map[string]cty.Value{"domain_name": cty.StringVal("Lab.Example.com"), "safe_mode_password_wo": cty.StringVal("s3ntinel")})
	p := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(c.Type()), ProposedNewState: c, Config: c}).PlannedState
	if !p.GetAttr("safe_mode_password_wo").IsNull() || strings.Contains(p.GoString(), "s3ntinel") || p.GetAttr("reboot_required").IsKnown() {
		t.Fatalf("planned %#v", p)
	}
	vals := p.AsValueMap()
	vals["revision"], vals["in_sync"], vals["reboot_required"] = cty.StringVal("r"), cty.True, cty.True
	prior := cty.ObjectVal(vals)
	lower := forestCfg(r, "azadmin", map[string]cty.Value{"domain_name": cty.StringVal("lab.example.com"), "safe_mode_password_wo": cty.StringVal("other")})
	if resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: lower, Config: lower}); len(resp.RequiresReplace) != 0 {
		t.Errorf("replace %v", resp.RequiresReplace)
	}
	// Nothing changed: no update, and reboot_required stays as it was.
	same := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: prior, Config: c}).PlannedState
	if !same.GetAttr("in_sync").IsKnown() || !same.GetAttr("reboot_required").True() {
		t.Errorf("planned %#v", same)
	}
}

// Removing the step forgets the forest and never reaches the host.
func TestWinForestRemoveForgets(t *testing.T) {
	r := resourceTypes["conn3x_windows_ad_forest"]
	prior := forestCfg(r, "azadmin", map[string]cty.Value{"domain_name": cty.StringVal("lab.test"), "in_sync": cty.True})
	resp := r.apply(context.Background(), providers.ApplyResourceChangeRequest{PriorState: prior, PlannedState: cty.NullVal(prior.Type()), Config: cty.NullVal(prior.Type())})
	if resp.Diagnostics.HasErrors() || !resp.NewState.IsNull() {
		t.Fatalf("%v %#v", resp.Diagnostics.Err(), resp.NewState)
	}
}

// Each problem is reported on its own attribute.
func TestWinADDiagnosticsNameTheirAttribute(t *testing.T) {
	for kind, c := range map[string]map[string]cty.Value{
		"conn3x_windows_ad_forest:netbios_name":  {"domain_name": cty.StringVal("lab.test"), "netbios_name": cty.StringVal("A.B")},
		"conn3x_windows_ad_forest:database_path": {"domain_name": cty.StringVal("lab.test"), "database_path": cty.StringVal(`\\s\x`)},
		"conn3x_windows_dns_client:interface":    {"interface": cty.StringVal("a*"), "servers": cty.ListVal([]cty.Value{cty.StringVal("10.0.0.4")})},
		"conn3x_windows_dns_client:servers":      {"servers": cty.ListVal([]cty.Value{cty.StringVal("0.0.0.0")})},
	} {
		rt, attr, _ := strings.Cut(kind, ":")
		r := resourceTypes[rt]
		d := r.validate(forestCfg(r, "azadmin", c))
		if len(d) != 1 || !tfdiags.GetAttribute(d[0]).Equals(cty.GetAttrPath(attr)) {
			t.Errorf("%s: %v", kind, d.Err())
		}
	}
}

func TestWinForestAction(t *testing.T) {
	f := windows.Forest{DomainName: "lab.test"}
	for _, c := range []struct {
		a       windows.ActualForest
		promote bool
		err     string
	}{
		{windows.ActualForest{}, true, ""},
		{windows.ActualForest{Forest: "LAB.test", Pending: true}, false, ""},
		{windows.ActualForest{Forest: "other.test"}, false, "already a domain controller in other.test"},
		{windows.ActualForest{Member: "corp.test"}, false, "member of corp.test"},
	} {
		promote, err := forestAction(f, c.a)
		if promote != c.promote || (err == nil) != (c.err == "") || (err != nil && !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%+v: %v, %v", c.a, promote, err)
		}
	}
}

func TestWinJoinAndDCValidate(t *testing.T) {
	join := resourceTypes["conn3x_windows_domain_membership"]
	dc := resourceTypes["conn3x_windows_ad_domain_controller"]
	okJoin := map[string]cty.Value{"domain": cty.StringVal("lab.test"), "username": cty.StringVal(`LAB\joiner`), "password_wo": cty.StringVal("x")}
	okDC := map[string]cty.Value{"domain_name": cty.StringVal("lab.test"), "username": cty.StringVal(`LAB\admin`), "password_wo": cty.StringVal("x"), "safe_mode_password_wo": cty.StringVal("y")}
	for _, c := range []struct {
		r     resourceType
		attrs map[string]cty.Value
	}{{join, okJoin}, {dc, okDC}} {
		for _, user := range []string{"azadmin", `LAB\azadmin`, `win2\azadmin`} {
			if d := c.r.validate(forestCfg(c.r, user, c.attrs)); d.HasErrors() {
				t.Errorf("%s: %v", user, d.Err())
			}
		}
	}
	with := func(base map[string]cty.Value, k string, v cty.Value) map[string]cty.Value {
		m := map[string]cty.Value{}
		for a, b := range base {
			m[a] = b
		}
		m[k] = v
		return m
	}
	for name, c := range map[string]struct {
		r     resourceType
		attrs map[string]cty.Value
		attr  string
	}{
		"join single label": {join, with(okJoin, "domain", cty.StringVal("lab")), "domain"},
		"join ou":           {join, with(okJoin, "ou", cty.StringVal("Servers")), "ou"},
		"join username":     {join, with(okJoin, "username", cty.StringVal("a\nb")), "username"},
		"join empty pw":     {join, with(okJoin, "password_wo", cty.StringVal("")), "password_wo"},
		"join timeout":      {join, with(okJoin, "timeout", cty.StringVal("soon")), "timeout"},
		"dc empty dsrm":     {dc, with(okDC, "safe_mode_password_wo", cty.StringVal("")), "safe_mode_password_wo"},
		"dc unc":            {dc, with(okDC, "sysvol_path", cty.StringVal(`\\s\x`)), "sysvol_path"},
		"dc drive root":     {dc, with(okDC, "database_path", cty.StringVal(`F:\`)), "database_path"},
		"dc username":       {dc, with(okDC, "username", cty.StringVal(`a:b`)), "username"},
		"dc single label":   {dc, with(okDC, "domain_name", cty.StringVal("lab")), "domain_name"},
	} {
		d := c.r.validate(forestCfg(c.r, "azadmin", c.attrs))
		if len(d) != 1 || !tfdiags.GetAttribute(d[0]).Equals(cty.GetAttrPath(c.attr)) {
			t.Errorf("%s: %v", name, d.Err())
		}
	}
	// A key login has nothing to reach the domain with, but adopting a host
	// that's already there needs no password: apply asks only when it joins.
	if d := join.validate(forestCfg(join, "azadmin", with(okJoin, "password_wo", cty.NullVal(cty.String)))); d.HasErrors() {
		t.Error(d.Err())
	}
	if d := dc.validate(forestCfg(dc, `.\azadmin`, okDC)); !d.HasErrors() || !strings.Contains(d.Err().Error(), "local account") {
		t.Errorf(".\\azadmin: %v", d.Err())
	}
	c := forestCfg(dc, `WIN2\azadmin`, okDC)
	if why := dcLockout(c, "win2"); !strings.Contains(why, "local account") {
		t.Errorf("host-named login: %q", why)
	}
	if why := dcLockout(forestCfg(dc, `LAB\azadmin`, okDC), "win2"); why != "" {
		t.Errorf("domain login: %q", why)
	}
}

// Passwords are in no plan or state, and removing either step forgets it
// without reaching the host.
func TestWinJoinAndDCPlanAndRemove(t *testing.T) {
	for rt, attrs := range map[string]map[string]cty.Value{
		"conn3x_windows_domain_membership":    {"domain": cty.StringVal("Lab.Test"), "username": cty.StringVal(`LAB\j`), "password_wo": cty.StringVal("s3ntinel")},
		"conn3x_windows_ad_domain_controller": {"domain_name": cty.StringVal("Lab.Test"), "username": cty.StringVal(`LAB\j`), "password_wo": cty.StringVal("s3ntinel"), "safe_mode_password_wo": cty.StringVal("s3ntinel")},
	} {
		r := resourceTypes[rt]
		c := forestCfg(r, "azadmin", attrs)
		p := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(c.Type()), ProposedNewState: c, Config: c}).PlannedState
		if strings.Contains(p.GoString(), "s3ntinel") || !p.GetAttr("password_wo").IsNull() || p.GetAttr("reboot_required").IsKnown() {
			t.Errorf("%s: planned %#v", rt, p)
		}
		vals := p.AsValueMap()
		vals["revision"], vals["in_sync"], vals["reboot_required"] = cty.StringVal("r"), cty.True, cty.True
		prior := cty.ObjectVal(vals)
		lower := prior.AsValueMap()
		for k, v := range lower {
			if v.Type() == cty.String && v.IsKnown() && !v.IsNull() && v.AsString() == "Lab.Test" {
				lower[k] = cty.StringVal("lab.test")
			}
		}
		if resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: cty.ObjectVal(lower), Config: c}); len(resp.RequiresReplace) != 0 {
			t.Errorf("%s: replace %v", rt, resp.RequiresReplace)
		}
		resp := r.apply(context.Background(), providers.ApplyResourceChangeRequest{PriorState: prior, PlannedState: cty.NullVal(prior.Type()), Config: cty.NullVal(prior.Type())})
		if resp.Diagnostics.HasErrors() || !resp.NewState.IsNull() {
			t.Errorf("%s: remove %v %#v", rt, resp.Diagnostics.Err(), resp.NewState)
		}
	}
}

func TestWinJoinAndDCAction(t *testing.T) {
	m := windows.Membership{Domain: "lab.test"}
	for _, c := range []struct {
		a    windows.ActualForest
		join bool
		err  string
	}{
		{windows.ActualForest{}, true, ""},
		{windows.ActualForest{Member: "LAB.test", Joined: "LAB.test"}, false, ""},
		{windows.ActualForest{Forest: "lab.test", Joined: "lab.test"}, false, ""}, // promoted later: still in the domain
		{windows.ActualForest{Member: "corp.test", Joined: "corp.test"}, false, "already in corp.test"},
	} {
		join, err := membershipAction(m, c.a)
		if join != c.join || (err == nil) != (c.err == "") || (err != nil && !strings.Contains(err.Error(), c.err)) {
			t.Errorf("join %+v: %v, %v", c.a, join, err)
		}
	}
	d := windows.DomainController{DomainName: "lab.test"}
	for _, c := range []struct {
		a       windows.ActualForest
		promote bool
		err     string
	}{
		{windows.ActualForest{}, true, ""},
		{windows.ActualForest{Member: "lab.test", Joined: "lab.test"}, true, ""},
		{windows.ActualForest{Forest: "lab.test", Pending: true, Joined: "LAB.test"}, false, ""},
		{windows.ActualForest{Forest: "other.test", Joined: "other.test"}, false, "already a domain controller in other.test"},
		{windows.ActualForest{Member: "corp.test", Joined: "corp.test"}, false, "member of corp.test"},
	} {
		promote, err := dcAction(d, c.a)
		if promote != c.promote || (err == nil) != (c.err == "") || (err != nil && !strings.Contains(err.Error(), c.err)) {
			t.Errorf("dc %+v: %v, %v", c.a, promote, err)
		}
	}
}
