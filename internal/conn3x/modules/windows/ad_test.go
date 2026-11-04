// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDNSClientValidate(t *testing.T) {
	for _, d := range []DNSClient{
		{Servers: []string{"10.0.0.4"}},
		{Interface: "Ethernet 2", Servers: []string{"10.0.0.4", "2001:db8::4"}},
	} {
		if err := d.Validate(); err != nil {
			t.Errorf("%+v: %v", d, err)
		}
	}
	for name, d := range map[string]DNSClient{
		"none":           {},
		"name":           {Servers: []string{"dc1.lab.test"}},
		"cidr":           {Servers: []string{"10.0.0.0/24"}},
		"zone":           {Servers: []string{"fe80::1%4"}},
		"mapped":         {Servers: []string{"::ffff:10.0.0.4"}},
		"twice":          {Servers: []string{"10.0.0.4", "10.0.0.4"}},
		"wildcard":       {Interface: "Ether*", Servers: []string{"10.0.0.4"}},
		"backtick":       {Interface: "Ether`*", Servers: []string{"10.0.0.4"}},
		"backtick alone": {Interface: "Ether`", Servers: []string{"10.0.0.4"}},
		"any4":           {Servers: []string{"0.0.0.0"}},
		"any6":           {Servers: []string{"::"}},
		"broadcast":      {Servers: []string{"255.255.255.255"}},
		"multicast":      {Servers: []string{"224.0.0.251"}},
		"mcast6":         {Servers: []string{"ff02::fb"}},
		"bracket":        {Interface: "[x]", Servers: []string{"10.0.0.4"}},
		"space end":      {Interface: "Ethernet ", Servers: []string{"10.0.0.4"}},
		"newline":        {Interface: "a\nb", Servers: []string{"10.0.0.4"}},
	} {
		if d.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDNSClientMatches(t *testing.T) {
	a := ActualDNSClient{Found: true, IPv4: []string{"10.0.0.4", "10.0.0.5"}, IPv6: []string{"fec0:0:0:ffff::1"}}
	for _, servers := range [][]string{
		{"10.0.0.4", "10.0.0.5"},                       // IPv6 left alone
		{"10.0.0.4", "fec0::ffff:0:0:0:1", "10.0.0.5"}, // each family in order, any text form
	} {
		if !(DNSClient{Servers: servers}).Matches(a) {
			t.Errorf("%v: no match", servers)
		}
	}
	for _, servers := range [][]string{{"10.0.0.5", "10.0.0.4"}, {"10.0.0.4"}, {"10.0.0.4", "10.0.0.5", "::1"}} {
		if (DNSClient{Servers: servers}).Matches(a) {
			t.Errorf("%v: matched", servers)
		}
	}
	if (DNSClient{Servers: []string{"10.0.0.4"}}).Matches(ActualDNSClient{}) {
		t.Error("matched a missing interface")
	}
}

func TestForestValidate(t *testing.T) {
	if err := (Forest{DomainName: "lab.example.com", NetBIOSName: "LAB", DatabasePath: `F:\NTDS`, SysvolPath: "F:/SYSVOL"}).Validate(); err != nil {
		t.Fatal(err)
	}
	for want, f := range map[string]Forest{
		"domain_name":  {DomainName: "lab"},
		"netbios_name": {DomainName: "lab.test", NetBIOSName: "A.B"},
		"sysvol_path":  {DomainName: "lab.test", SysvolPath: `\\s\x`},
	} {
		if attr, err := f.Check(); attr != want || err == nil {
			t.Errorf("%+v: %s, %v", f, attr, err)
		}
	}
	for name, f := range map[string]Forest{
		"single label": {DomainName: "lab"},
		"numeric tld":  {DomainName: "lab.123"},
		"underscore":   {DomainName: "my_lab.test"},
		"empty label":  {DomainName: "lab..test"},
		"trailing dot": {DomainName: "lab.test."},
		"quote":        {DomainName: "lab'.test"},
		"netbios long": {DomainName: "lab.test", NetBIOSName: "ABCDEFGHIJKLMNOP"},
		"netbios dot":  {DomainName: "lab.test", NetBIOSName: "LAB.X"},
		"unc":          {DomainName: "lab.test", DatabasePath: `\\srv\share`},
		"relative":     {DomainName: "lab.test", LogPath: `F:\a\..\b`},
		"drive root":   {DomainName: "lab.test", SysvolPath: `F:\`},
	} {
		if f.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestReadForest(t *testing.T) {
	for _, c := range []struct {
		value map[string]any
		want  ActualForest
	}{
		{map[string]any{"role": 2, "domain": "WORKGROUP", "root_dn": ""}, ActualForest{}},
		{map[string]any{"role": 3, "domain": "lab.test", "root_dn": ""}, ActualForest{Member: "lab.test"}},
		// Promoted, before its reboot: the role hasn't changed yet (3 was seen), and the marker is there.
		{map[string]any{"role": 3, "domain": "WORKGROUP", "root_dn": "DC=lab,DC=Example,DC=com", "marker": true}, ActualForest{Forest: "lab.Example.com", Pending: true}},
		// A root domain left behind, with no marker: not a forest.
		{map[string]any{"role": 2, "domain": "WORKGROUP", "root_dn": "DC=lab,DC=example,DC=com"}, ActualForest{}},
		{map[string]any{"role": 5, "domain": "lab.example.com", "root_dn": "DC=lab,DC=example,DC=com"}, ActualForest{Forest: "lab.example.com"}},
	} {
		got, err := ReadForest(context.Background(), &fake{answers: []map[string]any{{"ok": true, "value": c.value}}})
		if err != nil || got != c.want {
			t.Errorf("%v: got %+v, %v", c.value, got, err)
		}
	}
	f := Forest{DomainName: "LAB.example.com"}
	if !f.Matches(ActualForest{Forest: "lab.example.com"}) || f.Matches(ActualForest{Member: "lab.example.com"}) || f.Matches(ActualForest{Forest: "other.example.com"}) {
		t.Error("Matches")
	}
}

// The password travels as an argument on stdin and nowhere else, and an error
// that echoes it comes back blanked.
func TestApplyForestPassword(t *testing.T) {
	const secret = "s3ntinel-Dsrm!"
	f := &fake{answers: []map[string]any{{"ok": false, "error": "refused " + secret}}}
	_, err := ApplyForest(context.Background(), f, Forest{DomainName: "lab.test", DatabasePath: "F:/NTDS/"}, secret, time.Minute)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("err = %v", err)
	}
	args := f.sent[0]["args"].(map[string]any)
	if args["password"] != secret || args["database_path"] != `F:\NTDS` || strings.Contains(f.sent[0]["script"].(string), secret) {
		t.Errorf("sent %v", args)
	}
	if _, err := ApplyForest(context.Background(), &fake{}, Forest{DomainName: "lab.test"}, "", time.Minute); err == nil {
		t.Error("accepted an empty password")
	}
}
