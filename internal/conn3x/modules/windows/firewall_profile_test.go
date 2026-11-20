// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func TestFirewallProfileValidateAndRead(t *testing.T) {
	ctx := context.Background()
	on := true
	for want, p := range map[string]FirewallProfile{
		"domain, private or public": {Name: "work", Enabled: &on},
		"default_inbound":           {Name: "public", DefaultInbound: "deny"},
		"at least one":              {Name: "public"},
	} {
		if err := p.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want %q", p, err, want)
		}
	}
	// NotConfigured is Windows' default: on, inbound blocked, outbound allowed.
	f := &fake{answers: []map[string]any{ok(map[string]any{"enabled": "NotConfigured", "inbound": "NotConfigured", "outbound": "NotConfigured"})}}
	st, err := ReadFirewallProfile(ctx, f, "public", nil)
	if err != nil || !st.Enabled || st.Inbound != "block" || st.Outbound != "allow" || args(f, 0)["rules"] != false {
		t.Errorf("NotConfigured: %+v %v, sent %v", st, err, f.sent)
	}
	f = &fake{answers: []map[string]any{ok(map[string]any{"enabled": "False", "inbound": "Allow", "outbound": "Block", "conn_profile": "DomainAuthenticated"})}}
	conn := SSHConn{Client: netip.MustParseAddr("10.1.2.3"), Port: 2222}
	st, err = ReadFirewallProfile(ctx, f, "domain", &conn)
	if err != nil || st.Enabled || st.Inbound != "allow" || st.Outbound != "block" || st.ConnProfile != "domain" {
		t.Errorf("explicit: %+v %v", st, err)
	}
	if a := args(f, 0); a["rules"] != true || a["client"] != "10.1.2.3" || a["port"] != float64(2222) {
		t.Errorf("sent %v", a)
	}
	off := false
	if !(FirewallProfile{Name: "public", Enabled: &on, DefaultInbound: "block"}).Matches(ProfileState{Enabled: true, Inbound: "block", Outbound: "allow"}) ||
		(FirewallProfile{Name: "public", Enabled: &off}).Matches(ProfileState{Enabled: true}) ||
		!(FirewallProfile{Name: "public", DefaultOutbound: "allow"}).Matches(ProfileState{Enabled: false, Outbound: "allow"}) {
		t.Error("Matches")
	}

	f = &fake{answers: []map[string]any{ok(nil)}}
	if err := ApplyFirewallProfile(ctx, f, FirewallProfile{Name: "public", Enabled: &on, DefaultInbound: "block"}); err != nil {
		t.Fatal(err)
	}
	if a := args(f, 0); a["name"] != "Public" || a["enabled"] != true || a["inbound"] != "Block" || a["outbound"] != "" {
		t.Errorf("apply sent %v", a)
	}
	// Unset settings are sent as nothing, so the script leaves them alone.
	f = &fake{answers: []map[string]any{ok(nil)}}
	if err := ApplyFirewallProfile(ctx, f, FirewallProfile{Name: "domain", DefaultOutbound: "block"}); err != nil {
		t.Fatal(err)
	}
	if a := args(f, 0); a["enabled"] != nil || a["inbound"] != "" || a["outbound"] != "Block" {
		t.Errorf("apply of outbound only sent %v", a)
	}
}

func TestFirewallProfileLockout(t *testing.T) {
	on := true
	turnOn := FirewallProfile{Name: "public", Enabled: &on, DefaultInbound: "block"}
	offNow := ProfileState{Enabled: false, Inbound: "block"}
	client := SSHConn{Client: netip.MustParseAddr("203.0.113.7"), Port: 22}
	allowSSH := ProfileRule{Name: "OpenSSH-Server-In-TCP", Action: "Allow", Profile: 0, Protocol: "TCP", LocalPorts: []string{"22"}, SSHDProgram: true, SSHDService: true}
	adminNet := allowSSH
	adminNet.Name, adminNet.RemoteAddresses = "ssh-admin", []string{"10.0.0.0/8"}
	blockAll := ProfileRule{Name: "block-ssh", Action: "Block", Profile: 4, Protocol: "TCP", LocalPorts: []string{"22"}, SSHDProgram: true, SSHDService: true}
	otherProgram := allowSSH
	otherProgram.Name, otherProgram.LocalPorts, otherProgram.SSHDProgram = "chrome", []string{"Any"}, false
	localSubnet := allowSSH
	localSubnet.Name, localSubnet.RemoteAddresses = "ssh-subnet", []string{"LocalSubnet"}
	privateOnly := allowSSH
	privateOnly.Name, privateOnly.Profile = "ssh-private", 2
	for name, c := range map[string]struct {
		p     FirewallProfile
		st    ProfileState
		conn  SSHConn
		error string
	}{
		"an allow rule for port 22 in any profile": {turnOn, with(offNow, allowSSH), client, ""},
		"no rule at all": {turnOn, offNow, client, "no enabled rule in the public profile surely lets in 203.0.113.7"},
		// The #1135 lesson: a rule for another network doesn't keep this one in.
		"an allow rule for the admin network only": {turnOn, with(offNow, adminNet), client, "surely lets in"},
		// Conn3x may come through NAT, a VPN or a jump host, from outside the subnet.
		"an allow rule for the local subnet only":    {turnOn, with(offNow, localSubnet), client, "surely lets in"},
		"a block rule beats the allow rule":          {turnOn, with(offNow, allowSSH, blockAll), client, "rule block-ssh blocks inbound TCP from 203.0.113.7"},
		"a rule for another program doesn't count":   {turnOn, with(offNow, otherProgram), client, "surely lets in"},
		"a rule only in the private profile":         {turnOn, with(offNow, privateOnly), client, "surely lets in"},
		"loopback, which the firewall never filters": {turnOn, offNow, SSHConn{Client: netip.MustParseAddr("127.0.0.1"), Port: 22}, ""},
		"the connection is on the domain network":    {turnOn, ProfileState{Enabled: false, Inbound: "block", ConnProfile: "domain"}, client, ""},
		"turning it off":                             {FirewallProfile{Name: "public", Enabled: new(bool)}, offNow, client, ""},
		"inbound left allowed":                       {FirewallProfile{Name: "public", Enabled: &on, DefaultInbound: "allow"}, offNow, client, ""},
		"already on and blocking":                    {FirewallProfile{Name: "public", DefaultOutbound: "block"}, ProfileState{Enabled: true, Inbound: "block"}, client, ""},
		"blocking inbound on a profile that's on":    {FirewallProfile{Name: "public", DefaultInbound: "block"}, ProfileState{Enabled: true, Inbound: "allow"}, client, "surely lets in"},
		"client unknown, a rule from everywhere":     {turnOn, with(offNow, allowSSH), SSHConn{Port: 22}, ""},
		"client unknown, the admin network only":     {turnOn, with(offNow, adminNet), SSHConn{Port: 22}, "didn't report which address"},
	} {
		err := c.p.LockoutGuard(c.st, c.conn)
		if c.error == "" && err != nil || c.error != "" && (err == nil || !strings.Contains(err.Error(), c.error)) {
			t.Errorf("%s: %v, want %q", name, err, c.error)
		}
	}
}

func with(st ProfileState, rules ...ProfileRule) ProfileState {
	st.Rules = rules
	return st
}
