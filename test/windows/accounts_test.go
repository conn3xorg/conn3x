// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build windowshost

package windowshost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// accountName is a fresh local account name, removed when the test ends.
func accountName(t *testing.T, c *ssh.Client, prefix string) string {
	t.Helper()
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	name := prefix + hex.EncodeToString(b)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = ps.User(ctx, c, `param($A)
Get-LocalUser -Name $A.n -ErrorAction SilentlyContinue | Remove-LocalUser
Get-LocalGroup -Name $A.n -ErrorAction SilentlyContinue | Remove-LocalGroup`, map[string]any{"n": name}, time.Minute)
	})
	return name
}

// passwordWorks checks a password the way a logon would. Test code only: it
// passes the password to a .NET method, never a cmdlet.
func passwordWorks(t *testing.T, c *ssh.Client, user, password string) bool {
	t.Helper()
	res := run(t, c, `param($A)
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$ctx = [DirectoryServices.AccountManagement.PrincipalContext]::new('Machine')
$ctx.ValidateCredentials($A.u, $A.p)`, map[string]any{"u": user, "p": password})
	return strings.TrimSpace(res.Text) == "True"
}

func ptr[T any](v T) *T { return &v }

func TestUsersAndGroups(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	// A name that is valid on Windows and is code anywhere it isn't a literal.
	user := "$(x)'" + accountName(t, c, "c3")[2:]
	t.Cleanup(func() { _ = windows.ApplyUserRemove(context.Background(), c, user) })
	group := accountName(t, c, "c3g")
	// Every quote and expansion PowerShell, cmd.exe or a native argument
	// parser might act on, plus enough classes for the complexity policy.
	password := `Aa1!'"` + "`" + `$(New-Item C:\marker) %PATH% ;|& \"x\\`

	u := windows.User{Name: user, FullName: ptr("Conn3x test"), Description: ptr(`'; $(x) %PATH%`)}
	if err := u.Validate(); err != nil {
		t.Fatal(err)
	}
	a, err := windows.ReadUser(ctx, c, user)
	if err != nil || a.Exists {
		t.Fatalf("before: %+v, %v", a, err)
	}
	if err := windows.ApplyUser(ctx, c, u, a, nil); err == nil {
		t.Fatal("made an enabled user with no password")
	}
	if err := windows.ApplyUser(ctx, c, u, a, &password); err != nil {
		t.Fatal(err)
	}
	if a, err = windows.ReadUser(ctx, c, user); err != nil || !u.Matches(a) || !a.Enabled || !a.PasswordSet {
		t.Fatalf("after: %+v, %v", a, err)
	}
	if !passwordWorks(t, c, user, password) {
		t.Error("the hostile password didn't arrive byte for byte")
	}
	// Disabling, then a new password while disabled, then enabling.
	u.Disabled = ptr(true)
	if err := windows.ApplyUser(ctx, c, u, a, nil); err != nil {
		t.Fatal(err)
	}
	if a, _ = windows.ReadUser(ctx, c, user); a.Enabled || !u.Matches(a) {
		t.Errorf("disabled: %+v", a)
	}
	u.Disabled = ptr(false)
	if u.Matches(a) {
		t.Error("a disabled user matched enabled")
	}
	second := "Bb2@" + strings.Repeat("z", 12)
	if err := windows.ApplyUser(ctx, c, u, a, &second); err != nil {
		t.Fatal(err)
	}
	if !passwordWorks(t, c, user, second) || passwordWorks(t, c, user, password) {
		t.Error("the new password didn't replace the old one")
	}

	// A group, by name and by SID, with the user in it.
	g := windows.Group{Name: group, Description: ptr("Conn3x test"), Members: []string{user, "S-1-5-32-545"}}
	ga, err := windows.ReadGroup(ctx, c, g)
	if err != nil || ga.Exists || g.Matches(ga) {
		t.Fatalf("group before: %+v, %v", ga, err)
	}
	if err := windows.ApplyGroup(ctx, c, g, ga); err != nil {
		t.Fatal(err)
	}
	if ga, err = windows.ReadGroup(ctx, c, g); err != nil || !g.Matches(ga) || len(ga.Members) != 2 {
		t.Fatalf("group after: %+v, %v", ga, err)
	}
	// The same account, by its SID and in another case, is no change.
	same := windows.Group{Name: strings.ToUpper(group), Members: []string{a.SID, strings.ToUpper(user)}}
	if sa, err := windows.ReadGroup(ctx, c, same); err != nil || !same.Matches(sa) {
		t.Errorf("by SID: %+v, %v", sa, err)
	}
	// Additive leaves Users in; authoritative takes it out.
	only := windows.Group{Name: group, Members: []string{user}, Authoritative: true}
	if only.Matches(ga) {
		t.Error("authoritative matched with an extra member")
	}
	if err := windows.ApplyGroup(ctx, c, only, ga); err != nil {
		t.Fatal(err)
	}
	if ga, _ = windows.ReadGroup(ctx, c, only); !only.Matches(ga) || len(ga.Members) != 1 {
		t.Errorf("authoritative: %+v", ga)
	}
	// A member that doesn't exist yet: out of sync at read, an error at apply.
	later := windows.Group{Name: group, Members: []string{"c3-not-yet"}}
	if ga, err = windows.ReadGroup(ctx, c, later); err != nil || later.Matches(ga) {
		t.Errorf("unresolved: %+v, %v", ga, err)
	}
	if err := windows.ApplyGroup(ctx, c, later, ga); err == nil {
		t.Error("applied a member that doesn't exist")
	}
	// The login can't be taken out of Administrators.
	admins := windows.Group{Name: "Administrators", Members: []string{group}, Authoritative: true}
	aa, err := windows.ReadGroup(ctx, c, admins)
	if err != nil {
		t.Fatal(err)
	}
	// Only safe to try when the login is a direct member: otherwise the guard
	// has nothing to see and the apply would empty Administrators.
	me := strings.TrimSpace(run(t, c, `[Security.Principal.WindowsIdentity]::GetCurrent().User.Value`, nil).Text)
	if !slices.ContainsFunc(aa.Members, func(s string) bool { return strings.EqualFold(s, me) }) {
		t.Fatalf("the login %s isn't directly in Administrators %v; not trying the guard", me, aa.Members)
	}
	if err := windows.ApplyGroup(ctx, c, admins, aa); err == nil || !strings.Contains(err.Error(), "login Conn3x uses") {
		t.Fatalf("err = %v", err)
	}
	if aa2, _ := windows.ReadGroup(ctx, c, admins); len(aa2.Members) != len(aa.Members) {
		t.Errorf("Administrators changed: %v to %v", aa.Members, aa2.Members)
	}

	if err := windows.ApplyGroupRemove(ctx, c, group); err != nil {
		t.Fatal(err)
	}
	if err := windows.ApplyUserRemove(ctx, c, user); err != nil {
		t.Fatal(err)
	}
	if a, _ = windows.ReadUser(ctx, c, user); a.Exists {
		t.Error("remove left the user")
	}
	if err := windows.ApplyUserRemove(ctx, c, user); err != nil {
		t.Errorf("removing it twice: %v", err)
	}
	if got := strings.TrimSpace(run(t, c, `Test-Path -LiteralPath 'C:\marker'`, nil).Text); got != "False" {
		t.Error("a hostile value ran")
	}
}

// Hostile names are refused before a host, or read as the literal names they
// are; nothing in them runs.
func TestHostileAccountNames(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	for name, v := range hostile {
		u, g := windows.User{Name: v}, windows.Group{Name: v, Members: []string{v}}
		if u.Validate() == nil {
			if a, err := windows.ReadUser(ctx, c, v); err != nil || a.Exists {
				t.Errorf("%s: user %+v, %v", name, a, err)
			}
		}
		if g.Validate() == nil {
			if a, err := windows.ReadGroup(ctx, c, g); err != nil || a.Exists {
				t.Errorf("%s: group %+v, %v", name, a, err)
			}
		}
	}
	if got := strings.TrimSpace(run(t, c, `(Test-Path -LiteralPath 'C:\marker') -or (Test-Path -LiteralPath (Join-Path $HOME 'c3mark'))`, nil).Text); got != "False" {
		t.Error("a hostile value ran")
	}
	if got := strings.TrimSpace(run(t, c, `@(Get-LocalGroupMember -Group (Get-LocalGroup -SID S-1-5-32-544) | Where-Object { $_.SID.Value -like '*-501' }).Count`, nil).Text); got != "0" {
		t.Error("Guest is in Administrators")
	}
}

// With PowerShell's module and script block logging on, and process command
// lines audited, a password set through windows_user reaches no event log,
// no 4688 command line and no file Conn3x or sshd writes; and a password
// Windows refuses isn't in the error either.
func TestUserPasswordSentinel(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	user := accountName(t, c, "c3s")
	// Made at run time: a constant would sit in the test binary, which on a
	// runner is built under %TEMP%, where the files are searched.
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	sentinel := "s3ntinel-Pw-" + hex.EncodeToString(b) + "Q"
	weak := "s3ntinelweak" + hex.EncodeToString(b) // two character classes: Windows refuses it
	run(t, c, `$b = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
New-Item -Force -Path "$b\ModuleLogging\ModuleNames" | Out-Null
New-Item -Force -Path "$b\ScriptBlockLogging" | Out-Null
Set-ItemProperty -LiteralPath "$b\ModuleLogging" -Name EnableModuleLogging -Value 1
Set-ItemProperty -LiteralPath "$b\ModuleLogging\ModuleNames" -Name '*' -Value '*'
Set-ItemProperty -LiteralPath "$b\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1
$a = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -Force -Path $a | Out-Null
Set-ItemProperty -LiteralPath $a -Name ProcessCreationIncludeCmdLine_Enabled -Value 1
# Process Creation, by GUID, as subcategory names are localised.
auditpol.exe /set /subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null`, nil)
	restore := func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = ps.User(ctx, c, `Remove-Item -Recurse -Force -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue
auditpol.exe /set /subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030}' /success:disable | Out-Null`, nil, time.Minute)
	}
	t.Cleanup(restore)
	since := strings.TrimSpace(run(t, c, `(Get-Date).ToUniversalTime().ToString('o')`, nil).Text)

	u := windows.User{Name: user, Description: ptr("sentinel test")}
	a, err := windows.ReadUser(ctx, c, user)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.ApplyUser(ctx, c, u, a, ptr(weak)); err == nil {
		t.Log("this host's password policy took the weak password; it's still looked for below")
	} else if strings.Contains(err.Error(), weak) {
		t.Errorf("the refused password is in the error: %v", err)
	} else {
		t.Logf("refused as expected: %v", err)
	}
	if a, err = windows.ReadUser(ctx, c, user); err != nil {
		t.Fatal(err)
	}
	if err := windows.ApplyUser(ctx, c, u, a, ptr(sentinel)); err != nil {
		t.Fatal(err)
	}
	if a, err = windows.ReadUser(ctx, c, user); err != nil || !u.Matches(a) {
		t.Fatalf("%+v, %v", a, err)
	}
	// Once more on the existing account, through Set-LocalUser.
	if err := windows.ApplyUser(ctx, c, u, a, ptr(sentinel+"2")); err != nil {
		t.Fatal(err)
	}

	needles := []string{sentinel, weak, b64(sentinel), b64(weak)}
	res := run(t, c, `param($A)
$from = [datetime]$A.since
$n = @{}; $hits = @()
foreach ($q in @(@{ LogName = 'Microsoft-Windows-PowerShell/Operational' }, @{ LogName = 'Windows PowerShell' }, @{ LogName = 'Security'; Id = 4688 })) {
  $q.StartTime = $from
  foreach ($e in @(Get-WinEvent -FilterHashtable $q -ErrorAction SilentlyContinue)) {
    $n[$q.LogName] = 1 + [int]$n[$q.LogName]
    foreach ($w in $A.needles) { if ($e.Message.Contains($w)) { $hits += "$($q.LogName) event $($e.Id)" } }
  }
}
$counts = ($n.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' '
"$counts hits=$($hits -join ',')"`, map[string]any{"since": since, "needles": needles})
	got := strings.TrimSpace(res.Text)
	t.Log(got)
	for _, log := range []string{"Microsoft-Windows-PowerShell/Operational=", "Security=", "Windows PowerShell="} {
		if !strings.Contains(got, log) {
			t.Errorf("no %s events were recorded, so this proves nothing", strings.TrimSuffix(log, "="))
		}
	}
	if !strings.HasSuffix(got, "hits=") {
		t.Errorf("a password is in the event log: %s", got)
	}

	// Files, with logging off again so the search itself isn't recorded.
	restore()
	res = run(t, c, `param($A)
$hits = @()
foreach ($d in @('C:\ProgramData\ssh\logs', 'C:\Windows\Temp', $env:TEMP, 'C:\Windows\System32\LogFiles')) {
  foreach ($f in @(Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue)) {
    try { $text = [IO.File]::ReadAllText($f.FullName) } catch { continue }
    foreach ($w in $A.needles) { if ($text.Contains($w)) { $hits += $f.FullName } }
  }
}
"hits=$($hits -join ',')"`, map[string]any{"needles": needles})
	if got := strings.TrimSpace(res.Text); got != "hits=" {
		t.Errorf("a password is in a file: %s", got)
	}
	if !passwordWorks(t, c, user, sentinel+"2") {
		t.Error("the password wasn't set, so this proves nothing")
	}
}

// An account made disabled with no password stays that way until it has one.
func TestUserWithoutPassword(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	u := windows.User{Name: accountName(t, c, "c3n"), Disabled: ptr(true)}
	if err := windows.ApplyUser(ctx, c, u, windows.ActualUser{}, nil); err != nil {
		t.Fatal(err)
	}
	a, err := windows.ReadUser(ctx, c, u.Name)
	if err != nil || !a.Exists || a.Enabled || a.PasswordSet {
		t.Fatalf("made: %+v, %v", a, err)
	}
	u.Disabled = ptr(false)
	if err := windows.ApplyUser(ctx, c, u, a, nil); err == nil {
		t.Fatal("enabled an account with no password")
	}
	if a, _ = windows.ReadUser(ctx, c, u.Name); a.Enabled {
		t.Error("it's enabled anyway")
	}
}

// The host refuses to disable or delete the login, and to take the login's
// own groups out of a group it gets rights from, whatever the provider saw.
func TestLoginGuardsOnHost(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	login := env(t, "CONN3X_WIN_USER")
	if i := strings.LastIndex(login, `\`); i >= 0 {
		login = login[i+1:]
	}
	a, err := windows.ReadUser(ctx, c, login)
	if err != nil || !a.Exists {
		t.Fatalf("the login isn't a local user here: %+v, %v", a, err)
	}
	if err := windows.ApplyUser(ctx, c, windows.User{Name: login, Disabled: ptr(true)}, a, nil); err == nil || !strings.Contains(err.Error(), "logs in as") {
		t.Fatalf("disabling the login: %v", err)
	}
	if err := windows.ApplyUserRemove(ctx, c, login); err == nil || !strings.Contains(err.Error(), "logs in as") {
		t.Fatalf("deleting the login: %v", err)
	}
	// Users holds Authenticated Users and INTERACTIVE, which the login's token
	// carries: an authoritative list without them is refused.
	users := windows.Group{Name: "Users", Members: []string{login}, Authoritative: true}
	before, err := windows.ReadGroup(ctx, c, users)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.ApplyGroup(ctx, c, users, before); err == nil || !strings.Contains(err.Error(), "gets its rights through it") {
		t.Fatalf("emptying Users: %v", err)
	}
	if after, _ := windows.ReadGroup(ctx, c, users); len(after.Members) != len(before.Members) {
		t.Errorf("Users changed: %v to %v", before.Members, after.Members)
	}
	if !connect(t).Alive() {
		t.Error("the login no longer works")
	}
}

// A member whose SID no longer resolves doesn't break reading the group.
func TestGroupWithOrphanedMember(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	group := accountName(t, c, "c3o")
	g := windows.Group{Name: group}
	if err := windows.ApplyGroup(ctx, c, g, windows.ActualGroup{}); err != nil {
		t.Fatal(err)
	}
	const orphan = "S-1-5-21-1111111111-2222222222-3333333333-4242"
	run(t, c, `param($A) ([ADSI]('WinNT://./' + $A.g + ',group')).Add('WinNT://' + $A.s)`, map[string]any{"g": group, "s": orphan})
	if out := run(t, c, `param($A) try { Get-LocalGroupMember -Group $A.g | Out-Null; 'read' } catch { 'threw' }`, map[string]any{"g": group}).Text; !strings.Contains(out, "threw") {
		t.Logf("Get-LocalGroupMember didn't fail here (%s), so this shows only the ordinary path", strings.TrimSpace(out))
	}
	// read_group.ps1's fallback, run on its own: a workgroup host can't make
	// Get-LocalGroupMember fail, as a deleted domain account would.
	body, err := os.ReadFile("../../internal/conn3x/modules/windows/read_group.ps1")
	if err != nil {
		t.Fatal(err)
	}
	fallback := regexp.MustCompile(`(?s)catch \{.*?\n  (\(\[ADSI\].*?\n  \})`).FindSubmatch(body)
	if fallback == nil {
		t.Fatal("no ADSI fallback found in read_group.ps1")
	}
	res := run(t, c, "param($A)\n$g = Get-LocalGroup -Name $A.n\n"+string(fallback[1]), map[string]any{"n": group})
	if got := strings.TrimSpace(res.Text); !strings.EqualFold(got, orphan) {
		t.Errorf("ADSI fallback gave %q", got)
	}
	a, err := windows.ReadGroup(ctx, c, windows.Group{Name: group, Members: []string{orphan}})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Members) != 1 || !strings.EqualFold(a.Members[0], orphan) {
		t.Errorf("members %v", a.Members)
	}
}
