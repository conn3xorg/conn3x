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

func TestReadJoined(t *testing.T) {
	for _, c := range []struct {
		value map[string]any
		want  ActualForest
	}{
		// A workgroup's name is in domain too, so only PartOfDomain says joined.
		{map[string]any{"role": 2, "domain": "WORKGROUP", "part": false}, ActualForest{}},
		{map[string]any{"role": 3, "domain": "lab.test", "part": true}, ActualForest{Member: "lab.test", Joined: "lab.test"}},
		// Promoted from a member, before its reboot.
		{map[string]any{"role": 3, "domain": "lab.test", "part": true, "root_dn": "DC=lab,DC=test", "marker": true}, ActualForest{Forest: "lab.test", Pending: true, Joined: "lab.test"}},
		{map[string]any{"role": 4, "domain": "lab.test", "part": true, "root_dn": "DC=lab,DC=test"}, ActualForest{Forest: "lab.test", Joined: "lab.test"}},
	} {
		got, err := ReadForest(context.Background(), &fake{answers: []map[string]any{{"ok": true, "value": c.value}}})
		if err != nil || got != c.want {
			t.Errorf("%v: got %+v, %v", c.value, got, err)
		}
	}
	m := Membership{Domain: "Lab.Test"}
	if !m.Matches(ActualForest{Joined: "lab.test"}) || !m.Matches(ActualForest{Forest: "lab.test", Joined: "lab.test"}) || m.Matches(ActualForest{}) || m.Matches(ActualForest{Joined: "other.test"}) {
		t.Error("Membership.Matches")
	}
	d := DomainController{DomainName: "Lab.Test"}
	if !d.Matches(ActualForest{Forest: "lab.test", Joined: "lab.test"}) || d.Matches(ActualForest{Member: "lab.test", Joined: "lab.test"}) || d.Matches(ActualForest{Forest: "lab.test", Joined: "child.lab.test"}) {
		t.Error("DomainController.Matches")
	}
}

func TestMembershipCheck(t *testing.T) {
	for _, m := range []Membership{
		{Domain: "lab.test", Username: `LAB\joiner`},
		{Domain: "lab.test", Username: "joiner@lab.test", OU: "OU=Servers,DC=lab,DC=test"},
	} {
		if _, err := m.Check(); err != nil {
			t.Errorf("%+v: %v", m, err)
		}
	}
	for want, m := range map[string]Membership{
		"domain":   {Domain: "lab", Username: "a"},
		"ou":       {Domain: "lab.test", Username: "a", OU: "Servers"},
		"username": {Domain: "lab.test", Username: `LAB\a\b`},
	} {
		if attr, err := m.Check(); attr != want || err == nil {
			t.Errorf("%+v: %s, %v", m, attr, err)
		}
	}
	for _, u := range []string{"", `\a`, `a\`, "a\nb", "a:b", `a"b`, "a*"} {
		if checkUsername("username", u) == nil {
			t.Errorf("%q: accepted", u)
		}
	}
	if attr, _ := (DomainController{DomainName: "lab.test", Username: "a", SysvolPath: `F:\`}).Check(); attr != "sysvol_path" {
		t.Errorf("dc sysvol_path: %s", attr)
	}
	if attr, _ := (DomainController{DomainName: "lab.test"}).Check(); attr != "username" {
		t.Errorf("dc username: %s", attr)
	}
}

// Passwords travel as arguments on stdin and nowhere else, and an error that
// echoes them comes back blanked.
func TestApplyJoinAndDCPasswords(t *testing.T) {
	const pw, dsrm = "s3ntinel-Join!", "s3ntinel-Dsrm!"
	f := &fake{answers: []map[string]any{{"ok": false, "error": "refused " + pw}}}
	if _, err := ApplyMembership(context.Background(), f, Membership{Domain: "lab.test", Username: `LAB\j`}, pw, time.Minute); err == nil || strings.Contains(err.Error(), pw) {
		t.Fatalf("join: %v", err)
	}
	if args := f.sent[0]["args"].(map[string]any); args["password"] != pw || strings.Contains(f.sent[0]["script"].(string), pw) {
		t.Errorf("join sent %v", args)
	}
	f = &fake{answers: []map[string]any{{"ok": false, "error": "refused " + pw + " and " + dsrm}}}
	if _, err := ApplyDomainController(context.Background(), f, DomainController{DomainName: "lab.test", Username: `LAB\j`, DatabasePath: "F:/NTDS/"}, pw, dsrm, time.Minute); err == nil || strings.Contains(err.Error(), pw) || strings.Contains(err.Error(), dsrm) {
		t.Fatalf("dc: %v", err)
	}
	args := f.sent[0]["args"].(map[string]any)
	if args["password"] != pw || args["safe_mode_password"] != dsrm || args["database_path"] != `F:\NTDS` {
		t.Errorf("dc sent %v", args)
	}
	if _, err := ApplyMembership(context.Background(), &fake{}, Membership{Domain: "lab.test", Username: "j"}, "", time.Minute); err == nil {
		t.Error("join accepted an empty password")
	}
	if _, err := ApplyDomainController(context.Background(), &fake{}, DomainController{DomainName: "lab.test", Username: "j"}, "x", "", time.Minute); err == nil {
		t.Error("dc accepted an empty safe mode password")
	}
}

func TestChildDomain(t *testing.T) {
	c := ChildDomain{DomainName: "EMEA.lab.test", Username: `lab.test\admin`}
	if _, err := c.Check(); err != nil || c.Parent() != "lab.test" {
		t.Fatalf("%v, parent %q", err, c.Parent())
	}
	for _, u := range []string{"admin@lab.test", "admin@LAB.test", `lab.test\admin`} {
		if _, err := (ChildDomain{DomainName: "emea.lab.test", Username: u}).Check(); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	// The forest root, two levels up, is an ancestor too.
	if _, err := (ChildDomain{DomainName: "rome.emea.lab.test", Username: "admin@lab.test"}).Check(); err != nil {
		t.Error(err)
	}
	for want, c := range map[string]ChildDomain{
		"domain_name":  {DomainName: "lab.test", Username: "a@lab.test"},
		"netbios_name": {DomainName: "emea.lab.test", NetBIOSName: "A.B", Username: "a@lab.test"},
		"sysvol_path":  {DomainName: "emea.lab.test", SysvolPath: `F:\`, Username: "a@lab.test"},
		"username":     {DomainName: "emea.lab.test"},
	} {
		if attr, err := c.Check(); attr != want || err == nil {
			t.Errorf("%+v: %s, %v", c, attr, err)
		}
	}
	// Install-ADDSDomain finds the forest through DNS, so a NetBIOS name or
	// none won't do.
	for _, u := range []string{`LAB\admin`, "admin", "admin@lab", "admin@emea.lab.test", `EMEA.lab.test\admin`, "a@b@lab.test", "admin@other.test", "admin@xlab.test"} {
		if attr, _ := (ChildDomain{DomainName: "emea.lab.test", Username: u}).Check(); attr != "username" {
			t.Errorf("%s: %q", u, attr)
		}
	}
	// Promoted, before its reboot: still a workgroup, and only the marker
	// says which domain.
	got, err := ReadForest(context.Background(), &fake{answers: []map[string]any{{"ok": true, "value": map[string]any{
		"role": 2, "domain": "WORKGROUP", "root_dn": "DC=lab,DC=test", "marker": true, "promoted": "emea.lab.test"}}}})
	if want := (ActualForest{Forest: "lab.test", Pending: true, Promoted: "emea.lab.test"}); err != nil || got != want {
		t.Fatalf("pending: %+v, %v", got, err)
	}
	if !c.Matches(got) {
		t.Error("no match while pending")
	}
	for _, a := range []ActualForest{
		{Forest: "lab.test", Joined: "emea.lab.test"},
	} {
		if !c.Matches(a) {
			t.Errorf("%+v: no match", a)
		}
	}
	for _, a := range []ActualForest{
		{},
		{Member: "emea.lab.test", Joined: "emea.lab.test"},
		{Forest: "lab.test", Joined: "lab.test"},
		{Forest: "lab.test", Pending: true, Promoted: "apac.lab.test"},
		// A name left in the marker counts only while the marker is there.
		{Forest: "lab.test", Promoted: "emea.lab.test"},
	} {
		if c.Matches(a) {
			t.Errorf("%+v: matched", a)
		}
	}
}

func TestApplyChildDomainPasswords(t *testing.T) {
	const pw, dsrm = "s3ntinel-Admin!", "s3ntinel-Dsrm!"
	f := &fake{answers: []map[string]any{{"ok": false, "error": "refused " + pw + " and " + dsrm}}}
	if _, err := ApplyChildDomain(context.Background(), f, ChildDomain{DomainName: "emea.lab.test", Username: `lab.test\j`, SysvolPath: "F:/SYSVOL/"}, pw, dsrm, time.Minute); err == nil || strings.Contains(err.Error(), pw) || strings.Contains(err.Error(), dsrm) {
		t.Fatalf("err = %v", err)
	}
	args := f.sent[0]["args"].(map[string]any)
	if args["label"] != "emea" || args["parent"] != "lab.test" || args["password"] != pw || args["safe_mode_password"] != dsrm || args["sysvol_path"] != `F:\SYSVOL` {
		t.Errorf("sent %v", args)
	}
	if strings.Contains(f.sent[0]["script"].(string), pw) {
		t.Error("password in the script")
	}
	if _, err := ApplyChildDomain(context.Background(), &fake{}, ChildDomain{DomainName: "emea.lab.test", Username: "j"}, "", "x", time.Minute); err == nil {
		t.Error("accepted an empty password")
	}
}
