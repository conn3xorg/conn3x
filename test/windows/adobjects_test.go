// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build windowshost

package windowshost

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// onDC skips a test unless the host is a domain controller with AD answering.
func onDC(t *testing.T, c *ssh.Client) {
	t.Helper()
	a, err := windows.ReadOU(context.Background(), c, windows.OU{Name: "c3-none"})
	if err != nil || !a.AD {
		t.Skipf("not a domain controller: %+v, %v", a, err)
	}
}

// usn is each object's uSNChanged, which any write to it moves on.
func usn(t *testing.T, c *ssh.Client, dns ...string) string {
	t.Helper()
	return strings.TrimSpace(run(t, c, `param($A)
foreach ($d in $A.dns) { [string](Get-ADObject -Identity $d -Properties uSNChanged).uSNChanged }`, map[string]any{"dns": dns}).Text)
}

// The three AD modules on a real DC: create, read back, drift, membership,
// guards and removal, with names and a password that are code anywhere they
// aren't literals.
func TestADObjectsFlow(t *testing.T) {
	c := connect(t)
	onDC(t, c)
	ctx := context.Background()
	suffix := randHex(4)
	hostile := "$(x)'`%PATH%"
	// An OU name can't hold ( or ), so its hostile part is the rest.
	ouName := "c3 $x'`%PATH%" + suffix
	userName := "c3u'$" + suffix // 20 characters at most
	groupName := "c3g " + hostile + suffix
	password := "Aa1!'\"`$(New-Item C:\\marker) %PATH% ;|& \\\"" + suffix
	desc := `'; $(x) %PATH%`
	no := false

	o := windows.OU{Name: ouName, Description: &desc, Protected: &no}
	if _, err := o.Check(); err != nil {
		t.Fatal(err)
	}
	a, err := windows.ReadOU(ctx, c, o)
	if err != nil || a.Exists || a.Base == "" {
		t.Fatalf("before: %+v, %v", a, err)
	}
	if err := windows.ApplyOU(ctx, c, o, a); err != nil {
		t.Fatal(err)
	}
	if a, err = windows.ReadOU(ctx, c, o); err != nil || !o.Matches(a) {
		t.Fatalf("after: %+v, %v", a, err)
	}
	ouDN := a.DN
	t.Logf("OU %s", ouDN)
	t.Cleanup(func() {
		_, _ = ps.User(context.Background(), c, `param($A)
Set-ADOrganizationalUnit -Identity $A.dn -ProtectedFromAccidentalDeletion $false
Remove-ADOrganizationalUnit -Identity $A.dn -Recursive -Confirm:$false`, map[string]any{"dn": ouDN}, time.Minute)
	})

	u := windows.ADUser{Name: userName, Path: ouDN, UPN: ptr(userName + "@" + "c3.test"), GivenName: ptr("Al'ice"), DisplayName: ptr(hostile), Description: &desc}
	if _, err := u.Check(); err != nil {
		t.Fatal(err)
	}
	ua, err := windows.ReadADUser(ctx, c, u)
	if err != nil || ua.Exists {
		t.Fatalf("user before: %+v, %v", ua, err)
	}
	// A password the policy refuses is blanked from the error.
	weak := "s3" + suffix
	if err := windows.ApplyADUser(ctx, c, windows.ADUser{Name: "c3w" + suffix}, windows.ActualADUser{AD: true}, &weak); err == nil || strings.Contains(err.Error(), weak) {
		t.Errorf("weak password: %v", err)
	}
	run(t, c, `param($A) Get-ADUser -LDAPFilter "(sAMAccountName=$($A.n))" | Remove-ADUser -Confirm:$false`, map[string]any{"n": "c3w" + suffix})
	if err := windows.ApplyADUser(ctx, c, u, ua, &password); err != nil {
		t.Fatal(err)
	}
	if ua, err = windows.ReadADUser(ctx, c, u); err != nil || !u.Matches(ua) || !ua.Enabled || !ua.PasswordSet {
		t.Fatalf("user after: %+v, %v", ua, err)
	}
	if got := strings.TrimSpace(run(t, c, `param($A)
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
[DirectoryServices.AccountManagement.PrincipalContext]::new('Domain').ValidateCredentials($A.u, $A.p)`, map[string]any{"u": userName, "p": password}).Text); got != "True" {
		t.Errorf("the password doesn't log on: %s", got)
	}

	g := windows.ADGroup{Name: groupName, Path: ouDN, Scope: "global", Description: &desc, Members: []string{userName}}
	if _, err := g.Check(); err != nil {
		t.Fatal(err)
	}
	ga, err := windows.ReadADGroup(ctx, c, g)
	if err != nil || ga.Exists {
		t.Fatalf("group before: %+v, %v", ga, err)
	}
	if err := windows.ApplyADGroup(ctx, c, g, ga); err != nil {
		t.Fatal(err)
	}
	if ga, err = windows.ReadADGroup(ctx, c, g); err != nil || !g.Matches(ga) {
		t.Fatalf("group after: %+v, %v", ga, err)
	}
	if got := strings.TrimSpace(run(t, c, `param($A) (Get-ADGroupMember -Identity $A.g).SamAccountName`, map[string]any{"g": ga.DN}).Text); got != userName {
		t.Errorf("members: %q", got)
	}

	// Reads change nothing in the directory.
	before := usn(t, c, ouDN, ua.DN, ga.DN)
	for range 3 {
		if _, err := windows.ReadOU(ctx, c, o); err != nil {
			t.Fatal(err)
		}
		if _, err := windows.ReadADUser(ctx, c, u); err != nil {
			t.Fatal(err)
		}
		if _, err := windows.ReadADGroup(ctx, c, g); err != nil {
			t.Fatal(err)
		}
	}
	if after := usn(t, c, ouDN, ua.DN, ga.DN); after != before {
		t.Errorf("reads moved uSNChanged: %s, then %s", before, after)
	}

	// Hand changes are drift, and apply puts them back.
	run(t, c, `param($A)
Set-ADOrganizationalUnit -Identity $A.ou -Description 'by hand'
Set-ADUser -Identity $A.u -GivenName 'Bob'
Disable-ADAccount -Identity $A.u
New-ADUser -Name $A.x -SamAccountName $A.x -Path $A.ou
Add-ADGroupMember -Identity $A.g -Members $A.x
Remove-ADGroupMember -Identity $A.g -Members $A.u -Confirm:$false`, map[string]any{"ou": ouDN, "u": ua.DN, "g": ga.DN, "x": "c3x" + suffix})
	if a, _ = windows.ReadOU(ctx, c, o); o.Matches(a) {
		t.Error("OU description drift not seen")
	}
	if ua, _ = windows.ReadADUser(ctx, c, u); u.Matches(ua) {
		t.Error("user drift not seen")
	}
	g.Members = append(g.Members, "c3-nobody-"+suffix)
	if ga, _ = windows.ReadADGroup(ctx, c, g); g.Matches(ga) {
		t.Error("group drift not seen")
	}
	if err := windows.ApplyADGroup(ctx, c, g, ga); err == nil || !strings.Contains(err.Error(), "c3-nobody") {
		t.Errorf("unknown member: %v", err)
	}
	g.Members, g.Authoritative = []string{userName}, true
	if err := windows.ApplyOU(ctx, c, o, a); err != nil {
		t.Fatal(err)
	}
	if err := windows.ApplyADUser(ctx, c, u, ua, nil); err != nil {
		t.Fatal(err)
	}
	ga, _ = windows.ReadADGroup(ctx, c, g)
	if err := windows.ApplyADGroup(ctx, c, g, ga); err != nil {
		t.Fatal(err)
	}
	a, _ = windows.ReadOU(ctx, c, o)
	ua, _ = windows.ReadADUser(ctx, c, u)
	ga, _ = windows.ReadADGroup(ctx, c, g)
	if !o.Matches(a) || !u.Matches(ua) || !g.Matches(ga) || len(ga.Members) != 1 {
		t.Errorf("after reapply: %+v %+v %+v", a, ua, ga)
	}

	// Moved by hand, the user goes back to its path.
	run(t, c, `param($A) Move-ADObject -Identity $A.u -TargetPath ('CN=Users,' + (Get-ADDomain).DistinguishedName)`, map[string]any{"u": ua.DN})
	if ua, _ = windows.ReadADUser(ctx, c, u); u.Matches(ua) {
		t.Error("move not seen")
	}
	if err := windows.ApplyADUser(ctx, c, u, ua, nil); err != nil {
		t.Fatal(err)
	}
	if ua, _ = windows.ReadADUser(ctx, c, u); !u.Matches(ua) || !strings.EqualFold(ua.Parent, ouDN) {
		t.Errorf("not moved back: %+v", ua)
	}

	// Guards: the login stays in Domain Admins and stays enabled, and a
	// protected or full OU isn't deleted.
	login := strings.TrimSpace(run(t, c, `[Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[1]`, nil).Text)
	da := windows.ADGroup{Name: "Domain Admins", Members: []string{}, Authoritative: true}
	daa, err := windows.ReadADGroup(ctx, c, da)
	if err != nil || len(daa.Members) == 0 {
		t.Fatalf("Domain Admins: %+v, %v", daa, err)
	}
	if err := windows.ApplyADGroup(ctx, c, da, daa); err == nil || !strings.Contains(err.Error(), "lock Conn3x out") {
		t.Errorf("Domain Admins emptied: %v", err)
	}
	if after, _ := windows.ReadADGroup(ctx, c, da); len(after.Members) != len(daa.Members) {
		t.Errorf("Domain Admins changed: %v, then %v", daa.Members, after.Members)
	}
	me := windows.ADUser{Name: login, Enabled: &no}
	mea, err := windows.ReadADUser(ctx, c, me)
	if err != nil || !mea.Exists {
		t.Fatalf("login %s: %+v, %v", login, mea, err)
	}
	if err := windows.ApplyADUser(ctx, c, me, mea, nil); err == nil || !strings.Contains(err.Error(), "logs in as") {
		t.Errorf("disabled the login: %v", err)
	}
	if err := windows.ApplyOURemove(ctx, c, o); err == nil || !strings.Contains(err.Error(), "isn't empty") {
		t.Errorf("deleted a full OU: %v", err)
	}
	empty := windows.OU{Name: "c3e" + suffix, Path: ouDN}
	ea, _ := windows.ReadOU(ctx, c, empty)
	if err := windows.ApplyOU(ctx, c, empty, ea); err != nil {
		t.Fatal(err)
	}
	if err := windows.ApplyOURemove(ctx, c, empty); err == nil || !strings.Contains(err.Error(), "protected") {
		t.Errorf("deleted a protected OU: %v", err)
	}
	empty.Protected = &no
	ea, _ = windows.ReadOU(ctx, c, empty)
	if err := windows.ApplyOU(ctx, c, empty, ea); err != nil {
		t.Fatal(err)
	}
	if err := windows.ApplyOURemove(ctx, c, empty); err != nil {
		t.Errorf("empty OU: %v", err)
	}
	if ea, _ = windows.ReadOU(ctx, c, empty); ea.Exists {
		t.Error("empty OU still there")
	}

	// Removal deletes what it's asked to.
	if err := windows.ApplyADGroupRemove(ctx, c, groupName); err != nil {
		t.Error(err)
	}
	if err := windows.ApplyADUserRemove(ctx, c, userName); err != nil {
		t.Error(err)
	}
	if ga, _ = windows.ReadADGroup(ctx, c, g); ga.Exists {
		t.Error("group still there")
	}
	if ua, _ = windows.ReadADUser(ctx, c, u); ua.Exists {
		t.Error("user still there")
	}
}

// On a host that isn't a DC there's nothing to wait for, so the OU, group and
// user steps go straight to their own error. On a DC that's up, AD answers
// through the global catalog in seconds.
func TestWaitADAnswersQuickly(t *testing.T) {
	c := connect(t)
	start := time.Now()
	if err := windows.WaitAD(context.Background(), c, time.Minute); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 45*time.Second {
		t.Errorf("took %s", d)
	}
}
