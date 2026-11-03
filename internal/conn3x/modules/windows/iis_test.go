// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"strings"
	"testing"
)

func pool() AppPool {
	return AppPool{Name: "shop", Started: true, RuntimeVersion: "v4.0", PipelineMode: "integrated", Identity: "ApplicationPoolIdentity"}
}

func site() Site {
	return Site{Name: "shop", PhysicalPath: `C:\sites\shop`, AppPool: "shop", Started: true, Bindings: []Binding{
		{Protocol: "http", IP: "*", Port: 80, HostHeader: "Shop.Example.com"},
		{Protocol: "http", IP: "2001:db8::1", Port: 8080},
	}}
}

func TestAppPoolValidate(t *testing.T) {
	if err := pool().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*AppPool){
		"wildcard":  func(p *AppPool) { p.Name = "shop*" },
		"quote":     func(p *AppPool) { p.Name = "a'b" },
		"dot end":   func(p *AppPool) { p.Name = "shop." },
		"runtime":   func(p *AppPool) { p.RuntimeVersion = "v5.0" },
		"pipeline":  func(p *AppPool) { p.PipelineMode = "Integrated" },
		"identity":  func(p *AppPool) { p.Identity = "SpecificUser" },
		"too long":  func(p *AppPool) { p.Name = "a234567890123456789012345678901234567890123456789012345678901234567890" },
		"leading -": func(p *AppPool) { p.Name = "-x" },
	} {
		p := pool()
		change(&p)
		if p.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAppPoolMatches(t *testing.T) {
	a := ActualAppPool{Installed: true, Exists: true, State: "Started", AutoStart: true, RuntimeVersion: "v4.0", PipelineMode: "Integrated", Identity: "ApplicationPoolIdentity"}
	if !pool().Matches(a) {
		t.Fatal("no match")
	}
	for name, change := range map[string]func(*ActualAppPool){
		"no iis":     func(a *ActualAppPool) { a.Installed = false },
		"missing":    func(a *ActualAppPool) { a.Exists = false },
		"stopped":    func(a *ActualAppPool) { a.State = "Stopped" },
		"starting":   func(a *ActualAppPool) { a.State = "Starting" },
		"auto start": func(a *ActualAppPool) { a.AutoStart = false },
		"runtime":    func(a *ActualAppPool) { a.RuntimeVersion = "" },
		"pipeline":   func(a *ActualAppPool) { a.PipelineMode = "Classic" },
		"identity":   func(a *ActualAppPool) { a.Identity = "LocalSystem" },
	} {
		b := a
		change(&b)
		if pool().Matches(b) {
			t.Errorf("%s: matched", name)
		}
	}
	stopped := pool()
	stopped.Started = false
	if !stopped.Matches(ActualAppPool{Installed: true, Exists: true, State: "Stopped", RuntimeVersion: "v4.0", PipelineMode: "Integrated", Identity: "ApplicationPoolIdentity"}) {
		t.Error("stopped pool didn't match")
	}
}

func TestBindingInformation(t *testing.T) {
	for b, want := range map[Binding]string{
		{Protocol: "http", IP: "*", Port: 80}:                                 "*:80:",
		{Protocol: "http", IP: "10.0.0.4", Port: 8080, HostHeader: "A.B.com"}: "10.0.0.4:8080:a.b.com",
		{Protocol: "http", IP: "2001:DB8::0:1", Port: 80}:                     "[2001:db8::1]:80:",
		{Protocol: "http", IP: "::ffff:10.0.0.1", Port: 80}:                   "10.0.0.1:80:",
		{Protocol: "http", IP: "*", Port: 80, HostHeader: "*.example.com"}:    "*:80:*.example.com",
	} {
		if got, err := b.Information(); err != nil || got != want {
			t.Errorf("%+v: %q, %v", b, got, err)
		}
	}
	for name, b := range map[string]Binding{
		"https":     {Protocol: "https", IP: "*", Port: 443},
		"port 0":    {Protocol: "http", IP: "*", Port: 0},
		"port big":  {Protocol: "http", IP: "*", Port: 70000},
		"ip":        {Protocol: "http", IP: "localhost", Port: 80},
		"zone":      {Protocol: "http", IP: "fe80::1%4", Port: 80},
		"colon":     {Protocol: "http", IP: "*", Port: 80, HostHeader: "a:81"},
		"space":     {Protocol: "http", IP: "*", Port: 80, HostHeader: "a b"},
		"inner *":   {Protocol: "http", IP: "*", Port: 80, HostHeader: "a.*.com"},
		"injection": {Protocol: "http", IP: "*", Port: 80, HostHeader: "$(x)"},
	} {
		if _, err := b.Information(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSiteValidate(t *testing.T) {
	if err := site().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Site){
		"name":        func(s *Site) { s.Name = "a[b]" },
		"unc":         func(s *Site) { s.PhysicalPath = `\\srv\share` },
		"relative":    func(s *Site) { s.PhysicalPath = `sites\shop` },
		"env":         func(s *Site) { s.PhysicalPath = `C:\%x%\shop` },
		"pool":        func(s *Site) { s.AppPool = "a*" },
		"no bindings": func(s *Site) { s.Bindings = nil },
		"twice": func(s *Site) {
			s.Bindings = append(s.Bindings, Binding{Protocol: "http", IP: "*", Port: 80, HostHeader: "shop.example.com"})
		},
	} {
		s := site()
		change(&s)
		if s.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSiteMatches(t *testing.T) {
	a := ActualSite{Installed: true, Exists: true, State: "Started", AutoStart: true, PhysicalPath: `c:\Sites\shop\`, AppPool: "Shop",
		Bindings: []ActualBinding{{"http", "[2001:db8::1]:8080:"}, {"http", "*:80:shop.example.com"}}}
	if !site().Matches(a) {
		t.Fatal("no match")
	}
	unset := site()
	unset.AppPool = ""
	a.AppPool = "DefaultAppPool"
	if !unset.Matches(a) || site().Matches(a) {
		t.Error("app_pool unset should be left alone, and set should compare")
	}
	a.AppPool = "shop"
	for name, change := range map[string]func(*ActualSite){
		"no iis":     func(a *ActualSite) { a.Installed = false },
		"stopped":    func(a *ActualSite) { a.State = "Stopped" },
		"unknown":    func(a *ActualSite) { a.State = "Unknown" },
		"auto start": func(a *ActualSite) { a.AutoStart = false },
		"path":       func(a *ActualSite) { a.PhysicalPath = `C:\inetpub\wwwroot` },
		"extra":      func(a *ActualSite) { a.Bindings = append(a.Bindings, ActualBinding{"https", "*:443:"}) },
		"one gone":   func(a *ActualSite) { a.Bindings = a.Bindings[:1] },
		"port": func(a *ActualSite) {
			a.Bindings = []ActualBinding{{"http", "[2001:db8::1]:8081:"}, {"http", "*:80:shop.example.com"}}
		},
	} {
		b := a
		b.Bindings = append([]ActualBinding{}, a.Bindings...)
		change(&b)
		if site().Matches(b) {
			t.Errorf("%s: matched", name)
		}
	}
}

func TestApplySiteSends(t *testing.T) {
	f := &fake{answers: []map[string]any{{"ok": true, "value": nil}}}
	s := site()
	s.PhysicalPath = `C:/sites/shop/`
	if err := ApplySite(context.Background(), f, s); err != nil {
		t.Fatal(err)
	}
	a := f.sent[0]["args"].(map[string]any)
	bs := a["bindings"].([]any)
	if a["physical_path"] != `C:\sites\shop` || a["app_pool"] != "shop" || a["started"] != true || len(bs) != 2 ||
		bs[0].(map[string]any)["information"] != "*:80:shop.example.com" || bs[1].(map[string]any)["information"] != "[2001:db8::1]:8080:" {
		t.Errorf("sent %v", a)
	}
	s.AppPool = ""
	f = &fake{answers: []map[string]any{{"ok": true, "value": nil}}}
	if err := ApplySite(context.Background(), f, s); err != nil || f.sent[0]["args"].(map[string]any)["app_pool"] != nil {
		t.Errorf("unset pool sent %v, %v", f.sent[0]["args"], err)
	}
	if err := ApplySite(context.Background(), &fake{}, Site{Name: "x"}); err == nil {
		t.Error("sent an invalid site")
	}
}

func TestApplyAppPoolSends(t *testing.T) {
	f := &fake{answers: []map[string]any{{"ok": true, "value": nil}}}
	p := pool()
	p.PipelineMode = "classic"
	if err := ApplyAppPool(context.Background(), f, p); err != nil {
		t.Fatal(err)
	}
	if a := f.sent[0]["args"].(map[string]any); a["pipeline"] != "Classic" || a["runtime"] != "v4.0" || a["identity"] != "ApplicationPoolIdentity" || a["started"] != true {
		t.Errorf("sent %v", a)
	}
	if err := ApplyAppPoolRemove(context.Background(), &fake{}, "a*"); err == nil {
		t.Error("removed a wildcard name")
	}
}

// Both apply scripts carry the admin-only folder check from the library, and
// call it; the host tests prove what it refuses.
func TestIISAppliesCheckFolders(t *testing.T) {
	for name, call := range map[string]string{
		"apply_iis_site.ps1":     `Assert-AdminOnly $path -Folder -Inherited -Runner "the site's app pool"`,
		"apply_iis_app_pool.ps1": `Assert-AdminOnly $vp -Folder -Inherited -Runner`,
		"apply_task.ps1":         `Assert-AdminOnly ([string]$A.execute)`,
	} {
		body := script(name).Body
		if !strings.Contains(body, "function Assert-AdminOnly(") || !strings.Contains(body, call) {
			t.Errorf("%s doesn't check its folders", name)
		}
	}
}
