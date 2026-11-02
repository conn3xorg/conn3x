// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"strings"
	"testing"
)

func TestCanonicalAddress(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.0/8":                "10.0.0.0/8",
		"10.0.0.0/255.0.0.0":        "10.0.0.0/8",
		"192.0.2.7/255.255.255.255": "192.0.2.7",
		"192.0.2.7/32":              "192.0.2.7",
		"192.0.2.7":                 "192.0.2.7",
		"2001:DB8::/32":             "2001:db8::/32",
		"10.0.0.1-10.0.0.9":         "10.0.0.1-10.0.0.9",
		"localsubnet":               "LocalSubnet",
		"2001:db8::1-2001:db8::ff":  "2001:db8::1-2001:db8::ff",
		"172.16.0.0/255.240.0.0":    "172.16.0.0/12",
		"0.0.0.0/0":                 "0.0.0.0/0",
	} {
		if got, err := canonicalAddress(in); err != nil || got != want {
			t.Errorf("%s: %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"10.0.0.5/8", "10.0.0.0/255.0.255.0", "10.0.0.9-10.0.0.1", "10.0.0.1-2001:db8::1", "any'; x", "fe80::1%eth0", "*", "10.0.0.0/33", ""} {
		if _, err := canonicalAddress(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestFirewallValidate(t *testing.T) {
	ok := FirewallRule{Name: "Conn3x web (443)", Protocol: "tcp", LocalPorts: []string{"443", "8000-8100"}, RemoteAddresses: []string{"10.0.0.0/8"}, Profiles: []string{"domain"}, Enabled: true}.WithDefaults()
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]FirewallRule{
		"wildcard name":   {Name: "web*"},
		"bracket name":    {Name: "[web]"},
		"quote name":      {Name: "web'; x"},
		"ports, any":      {Name: "a", LocalPorts: []string{"80"}},
		"port 0":          {Name: "a", Protocol: "tcp", LocalPorts: []string{"0"}},
		"port too big":    {Name: "a", Protocol: "tcp", LocalPorts: []string{"65536"}},
		"backwards range": {Name: "a", Protocol: "tcp", LocalPorts: []string{"90-80"}},
		"port list":       {Name: "a", Protocol: "tcp", LocalPorts: []string{"80,443"}},
		"bad protocol":    {Name: "a", Protocol: "gre"},
		"bad direction":   {Name: "a", Direction: "in"},
		"bad profile":     {Name: "a", Profiles: []string{"work"}},
		"host bits":       {Name: "a", RemoteAddresses: []string{"10.1.2.3/8"}},
		"control display": {Name: "a", DisplayName: "a\nb"},
	} {
		if f.WithDefaults().Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFirewallBlocksSSH(t *testing.T) {
	base := FirewallRule{Name: "a", Action: "block", Enabled: true}.WithDefaults()
	for name, tc := range map[string]struct {
		f    func(FirewallRule) FirewallRule
		want bool
	}{
		"everything":        {func(f FirewallRule) FirewallRule { return f }, true},
		"tcp 22":            {func(f FirewallRule) FirewallRule { f.Protocol, f.LocalPorts = "tcp", []string{"22"}; return f }, true},
		"tcp range over 22": {func(f FirewallRule) FirewallRule { f.Protocol, f.LocalPorts = "tcp", []string{"1-1024"}; return f }, true},
		"tcp 80":            {func(f FirewallRule) FirewallRule { f.Protocol, f.LocalPorts = "tcp", []string{"80"}; return f }, false},
		"udp":               {func(f FirewallRule) FirewallRule { f.Protocol = "udp"; return f }, false},
		"from somewhere":    {func(f FirewallRule) FirewallRule { f.RemoteAddresses = []string{"192.0.2.0/24"}; return f }, false},
		"outbound":          {func(f FirewallRule) FirewallRule { f.Direction = "outbound"; return f }, false},
		"disabled":          {func(f FirewallRule) FirewallRule { f.Enabled = false; return f }, false},
		"allow":             {func(f FirewallRule) FirewallRule { f.Action = "allow"; return f }, false},
	} {
		if got := tc.f(base).Blocks(22); got != tc.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

// What Windows reports back matches what was asked, in Windows' own forms.
func TestFirewallMatches(t *testing.T) {
	f := FirewallRule{Name: "web", Protocol: "tcp", LocalPorts: []string{"8000-8100", "443"}, RemoteAddresses: []string{"10.0.0.0/8", "192.0.2.7"}, Enabled: true}
	a := ActualFirewallRule{Exists: true, DisplayName: "web", Direction: "Inbound", Action: "Allow", Enabled: true, Profile: 0, Protocol: "TCP",
		LocalPorts: []string{"443", "8000-8100"}, RemoteAddresses: []string{"192.0.2.7", "10.0.0.0/255.0.0.0"}}
	if !f.Matches(a) {
		t.Fatal("didn't match Windows' forms")
	}
	a.Profile = 7
	if !f.Matches(a) {
		t.Error("all three profiles isn't any")
	}
	for name, change := range map[string]func(*ActualFirewallRule){
		"port":     func(a *ActualFirewallRule) { a.LocalPorts = []string{"443"} },
		"address":  func(a *ActualFirewallRule) { a.RemoteAddresses = []string{"Any"} },
		"action":   func(a *ActualFirewallRule) { a.Action = "Block" },
		"disabled": func(a *ActualFirewallRule) { a.Enabled = false },
		"profile":  func(a *ActualFirewallRule) { a.Profile = 4 },
		"protocol": func(a *ActualFirewallRule) { a.Protocol = "UDP" },
		"missing":  func(a *ActualFirewallRule) { a.Exists = false },
	} {
		b := a
		change(&b)
		if f.Matches(b) {
			t.Errorf("%s: drift matched", name)
		}
	}
	open := FirewallRule{Name: "x", Enabled: true}
	if !open.Matches(ActualFirewallRule{Exists: true, DisplayName: "x", Direction: "Inbound", Action: "Allow", Enabled: true, Protocol: "Any", LocalPorts: []string{"Any"}, RemoteAddresses: []string{"Any"}}) {
		t.Error("Windows' Any didn't match unset")
	}
}

func TestApplyFirewallRuleSends(t *testing.T) {
	f := &fake{answers: []map[string]any{{"ok": true}}}
	r := FirewallRule{Name: "web", Protocol: "tcp", LocalPorts: []string{"443"}, RemoteAddresses: []string{"10.0.0.0/8"}, Profiles: []string{"domain", "private"}, Enabled: true}
	if err := ApplyFirewallRule(context.Background(), f, r); err != nil {
		t.Fatal(err)
	}
	args := f.sent[0]["args"].(map[string]any)
	if args["protocol"] != "TCP" || args["direction"] != "Inbound" || args["display_name"] != "web" || strings.Join(toStrings(args["profiles"]), ",") != "Domain,Private" {
		t.Errorf("sent %v", args)
	}
	if err := ApplyFirewallRule(context.Background(), &fake{}, FirewallRule{Name: "a*"}); err == nil {
		t.Error("sent a wildcard name")
	}
}

func toStrings(v any) []string {
	var out []string
	for _, e := range v.([]any) {
		out = append(out, e.(string))
	}
	return out
}
