// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"net/netip"
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
	me := SSHConn{Client: netip.MustParseAddr("203.0.113.9"), Port: 22}
	anon := SSHConn{Port: 22} // plan time: no client known
	base := FirewallRule{Name: "a", Action: "block", Enabled: true}.WithDefaults()
	for name, tc := range map[string]struct {
		f        func(FirewallRule) FirewallRule
		me, anon bool
	}{
		"everything":         {func(f FirewallRule) FirewallRule { return f }, true, true},
		"tcp 22":             {func(f FirewallRule) FirewallRule { f.Protocol, f.LocalPorts = "tcp", []string{"22"}; return f }, true, true},
		"range over 22":      {func(f FirewallRule) FirewallRule { f.Protocol, f.LocalPorts = "tcp", []string{"1-1024"}; return f }, true, true},
		"tcp 80":             {func(f FirewallRule) FirewallRule { f.Protocol, f.LocalPorts = "tcp", []string{"80"}; return f }, false, false},
		"udp":                {func(f FirewallRule) FirewallRule { f.Protocol = "udp"; return f }, false, false},
		"every v4 and v6":    {func(f FirewallRule) FirewallRule { f.RemoteAddresses = []string{"0.0.0.0/0", "::/0"}; return f }, true, true},
		"full v4 range":      {func(f FirewallRule) FirewallRule { f.RemoteAddresses = []string{"0.0.0.0-255.255.255.255"}; return f }, true, true},
		"LocalSubnet":        {func(f FirewallRule) FirewallRule { f.RemoteAddresses = []string{"LocalSubnet"}; return f }, true, true},
		"subnet with client": {func(f FirewallRule) FirewallRule { f.RemoteAddresses = []string{"203.0.113.0/24"}; return f }, true, false},
		"range with client":  {func(f FirewallRule) FirewallRule { f.RemoteAddresses = []string{"203.0.113.1-203.0.113.20"}; return f }, true, false},
		"the client":         {func(f FirewallRule) FirewallRule { f.RemoteAddresses = []string{"203.0.113.9"}; return f }, true, false},
		"somewhere else": {func(f FirewallRule) FirewallRule {
			f.RemoteAddresses = []string{"192.0.2.0/24", "2001:db8::/32"}
			return f
		}, false, false},
		"outbound": {func(f FirewallRule) FirewallRule { f.Direction = "outbound"; return f }, false, false},
		"disabled": {func(f FirewallRule) FirewallRule { f.Enabled = false; return f }, false, false},
		"allow":    {func(f FirewallRule) FirewallRule { f.Action = "allow"; return f }, false, false},
	} {
		if got := tc.f(base).BlocksSSH(me); got != tc.me {
			t.Errorf("%s, known client: %v", name, got)
		}
		if got := tc.f(base).BlocksSSH(anon); got != tc.anon {
			t.Errorf("%s, at plan: %v", name, got)
		}
	}
	// sshd's own port, as the host reports it, is what counts.
	if (FirewallRule{Name: "a", Action: "block", Protocol: "tcp", LocalPorts: []string{"22"}, Enabled: true}).WithDefaults().BlocksSSH(SSHConn{Port: 2222}) {
		t.Error("blocking 22 counted against sshd on 2222")
	}
}

// The rule that lets SSH in can't be deleted, disabled or narrowed.
func TestSSHGuard(t *testing.T) {
	me := SSHConn{Client: netip.MustParseAddr("203.0.113.9"), Port: 22}
	have := ActualFirewallRule{Exists: true, DisplayName: "OpenSSH", Direction: "Inbound", Action: "Allow", Enabled: true, Protocol: "TCP",
		LocalPorts: []string{"22"}, RemoteAddresses: []string{"Any"}, Profile: 0}
	keep := FirewallRule{Name: "OpenSSH-Server-In-TCP", Protocol: "tcp", LocalPorts: []string{"22"}, Enabled: true, Description: nil}
	if err := SSHGuard(me, have, &keep); err != nil {
		t.Errorf("keeping it open: %v", err)
	}
	wider := keep
	wider.LocalPorts = []string{"22", "2222"}
	if err := SSHGuard(me, have, &wider); err != nil {
		t.Errorf("widening it: %v", err)
	}
	if SSHGuard(me, have, nil) == nil {
		t.Error("deleted the rule that lets SSH in")
	}
	for name, change := range map[string]func(*FirewallRule){
		"disabled":         func(f *FirewallRule) { f.Enabled = false },
		"other addresses":  func(f *FirewallRule) { f.RemoteAddresses = []string{"192.0.2.0/24"} },
		"other port":       func(f *FirewallRule) { f.LocalPorts = []string{"2222"} },
		"block":            func(f *FirewallRule) { f.Action = "block" },
		"one profile":      func(f *FirewallRule) { f.Profiles = []string{"domain"} },
		"udp":              func(f *FirewallRule) { f.Protocol = "udp" },
		"outbound instead": func(f *FirewallRule) { f.Direction = "outbound" },
	} {
		w := keep
		change(&w)
		if SSHGuard(me, have, &w) == nil {
			t.Errorf("%s: allowed", name)
		}
	}
	// A rule that doesn't let this connection in is anyone's to change.
	other := have
	other.LocalPorts = []string{"443"}
	if err := SSHGuard(me, other, nil); err != nil {
		t.Errorf("deleting an unrelated rule: %v", err)
	}
	narrow := have
	narrow.Profile = 1
	if err := SSHGuard(me, narrow, &FirewallRule{Name: "x", Protocol: "tcp", LocalPorts: []string{"22"}, Profiles: []string{"domain", "private"}, Enabled: true}); err != nil {
		t.Errorf("adding a profile: %v", err)
	}
}

func TestReadSSHConn(t *testing.T) {
	for in, want := range map[string]SSHConn{
		"203.0.113.9 50123 10.42.0.4 22":   {Client: netip.MustParseAddr("203.0.113.9"), Port: 22},
		"::ffff:203.0.113.9 1 10.0.0.1 22": {Client: netip.MustParseAddr("203.0.113.9"), Port: 22},
		"":                                 {Port: 2222},
	} {
		got, err := ReadSSHConn(context.Background(), &fake{answers: []map[string]any{{"ok": true, "value": in}}}, 2222)
		if err != nil || got != want {
			t.Errorf("%q: %+v, %v", in, got, err)
		}
	}
}

// What Windows reports back matches what was asked, in Windows' own forms.
func TestFirewallMatches(t *testing.T) {
	f := FirewallRule{Name: "web", DisplayName: "web", Protocol: "tcp", LocalPorts: []string{"8000-8100", "443"}, RemoteAddresses: []string{"10.0.0.0/8", "192.0.2.7"}, Enabled: true}
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
	if args["protocol"] != "TCP" || args["direction"] != "Inbound" || args["display_name"] != nil || strings.Join(toStrings(args["profiles"]), ",") != "Domain,Private" {
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

// An unset display name is left alone, so adopting a rule doesn't rename it.
func TestFirewallDisplayNameLeftAlone(t *testing.T) {
	f := FirewallRule{Name: "OpenSSH-Server-In-TCP", Protocol: "tcp", LocalPorts: []string{"22"}, Enabled: true}
	a := ActualFirewallRule{Exists: true, DisplayName: "OpenSSH Server (sshd)", Direction: "Inbound", Action: "Allow", Enabled: true, Protocol: "TCP", LocalPorts: []string{"22"}}
	if !f.Matches(a) {
		t.Error("an unset display name counted as drift")
	}
	fk := &fake{answers: []map[string]any{{"ok": true}}}
	if err := ApplyFirewallRule(context.Background(), fk, f); err != nil {
		t.Fatal(err)
	}
	if v, ok := fk.sent[0]["args"].(map[string]any)["display_name"]; !ok || v != nil {
		t.Errorf("display_name sent as %v", v)
	}
}

// The three ways the guard used to fail open.
func TestSSHGuardFailsClosed(t *testing.T) {
	unknown := SSHConn{Port: 22}
	allow := ActualFirewallRule{Exists: true, Direction: "Inbound", Action: "Allow", Enabled: true, Protocol: "TCP", LocalPorts: []string{"22"}, RemoteAddresses: []string{"10.0.0.0/255.0.0.0"}}
	// No SSH_CONNECTION: a block on part of the address space, or any change
	// or delete of a rule that lets the port in, is refused.
	block := FirewallRule{Name: "b", Action: "block", Protocol: "tcp", LocalPorts: []string{"22"}, RemoteAddresses: []string{"10.0.0.0/8"}, Enabled: true}
	if SSHGuard(unknown, ActualFirewallRule{}, &block) == nil {
		t.Error("unknown client: a block on 10.0.0.0/8 passed")
	}
	if SSHGuard(unknown, allow, nil) == nil {
		t.Error("unknown client: deleted an allow on 10.0.0.0/8")
	}
	off := FirewallRule{Name: "a", Protocol: "tcp", LocalPorts: []string{"22"}, RemoteAddresses: []string{"10.0.0.0/8"}}
	if SSHGuard(unknown, allow, &off) == nil {
		t.Error("unknown client: disabled an allow on 10.0.0.0/8")
	}
	web := FirewallRule{Name: "w", Protocol: "tcp", LocalPorts: []string{"443"}, Enabled: true}
	if err := SSHGuard(unknown, ActualFirewallRule{}, &web); err != nil {
		t.Errorf("unknown client: a rule for another port: %v", err)
	}
	// Plan's early check stays loose: only a block from everywhere.
	if block.WithDefaults().BlocksSSH(unknown) {
		t.Error("plan refused a block on 10.0.0.0/8")
	}

	// LocalSubnet counts against a block, never for the rule being kept.
	me := SSHConn{Client: netip.MustParseAddr("198.51.100.7"), Port: 22}
	open := ActualFirewallRule{Exists: true, Direction: "Inbound", Action: "Allow", Enabled: true, Protocol: "TCP", LocalPorts: []string{"22"}, RemoteAddresses: []string{"Any"}}
	local := FirewallRule{Name: "OpenSSH-Server-In-TCP", Protocol: "tcp", LocalPorts: []string{"22"}, RemoteAddresses: []string{"LocalSubnet"}, Enabled: true}
	if SSHGuard(me, open, &local) == nil {
		t.Error("narrowed the SSH rule to LocalSubnet")
	}
	blockLocal := FirewallRule{Name: "b", Action: "block", Protocol: "tcp", LocalPorts: []string{"22"}, RemoteAddresses: []string{"LocalSubnet"}, Enabled: true}
	if SSHGuard(me, ActualFirewallRule{}, &blockLocal) == nil {
		t.Error("a block on LocalSubnet passed")
	}
	if SSHGuard(me, ActualFirewallRule{Exists: true, Direction: "Inbound", Action: "Allow", Enabled: true, Protocol: "TCP", LocalPorts: []string{"22"}, RemoteAddresses: []string{"LocalSubnet"}}, nil) == nil {
		t.Error("deleted an allow on LocalSubnet")
	}
}

// A link-local client keeps no zone, so it matches a rule's address.
func TestSSHConnDropsZone(t *testing.T) {
	c, err := ReadSSHConn(context.Background(), &fake{answers: []map[string]any{{"ok": true, "value": "fe80::1%4 50000 fe80::2%4 22"}}}, 22)
	if err != nil || c.Client != netip.MustParseAddr("fe80::1") {
		t.Fatalf("%+v, %v", c, err)
	}
	block := FirewallRule{Name: "b", Action: "block", Protocol: "tcp", LocalPorts: []string{"22"}, RemoteAddresses: []string{"fe80::/64"}, Enabled: true}
	if SSHGuard(c, ActualFirewallRule{}, &block) == nil {
		t.Error("a block on fe80::/64 passed for a link-local client")
	}
	have := ActualFirewallRule{Exists: true, Direction: "Inbound", Action: "Allow", Enabled: true, Protocol: "TCP", LocalPorts: []string{"22"}, RemoteAddresses: []string{"fe80::1"}}
	if SSHGuard(c, have, nil) == nil {
		t.Error("deleted the allow for a link-local client")
	}
}
