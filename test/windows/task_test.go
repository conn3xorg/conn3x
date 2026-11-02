// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build windowshost

package windowshost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

const cmdExe = `C:\Windows\System32\cmd.exe`

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// taskName is a fresh task in \Conn3xTest\, removed when the test ends.
func newTask(t *testing.T, c *ssh.Client) windows.Task {
	t.Helper()
	tk := windows.Task{Path: `\Conn3xTest\`, Name: "c3t " + randHex(4), Execute: cmdExe, User: "SYSTEM", Enabled: true, AllowInterpreter: true}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = windows.ApplyTaskRemove(ctx, c, tk.Path, tk.Name)
	})
	return tk
}

// runTask starts a task and waits for the file it should write.
func runTask(t *testing.T, c *ssh.Client, tk windows.Task, file string) bool {
	t.Helper()
	res := run(t, c, `param($A)
Start-ScheduledTask -TaskPath $A.path -TaskName $A.name
for ($i = 0; $i -lt 60; $i++) { if ([IO.File]::Exists($A.file)) { return 'ran' }; Start-Sleep -Milliseconds 500 }
'not run: ' + (Get-ScheduledTaskInfo -TaskPath $A.path -TaskName $A.name).LastTaskResult`, map[string]any{"path": tk.Path, "name": tk.Name, "file": file})
	got := strings.TrimSpace(res.Text)
	if got != "ran" {
		t.Logf("task: %s", got)
	}
	return got == "ran"
}

func TestTaskAsSystem(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	// Somewhere only administrators can change: once the task has run, its
	// output exists, and paths in arguments that exist are checked.
	out := tempDir(t, c) + `\c3task-` + randHex(4) + ".txt"
	tk := newTask(t, c)
	desc := `'; $(md c3mark) %PATH%`
	tk.Description = &desc
	tk.Arguments = `/c echo "a b" $(x) > ` + out
	tk.WorkingDirectory = `C:\Windows\System32`
	tk.Triggers = []windows.TaskTrigger{{Type: "daily", At: "2030-01-01T03:00:00", DaysInterval: 2}, {Type: "once", At: "2030-06-01T12:30:00"}, {Type: "boot"}}
	a, err := windows.ReadTask(ctx, c, tk)
	if err != nil || a.Exists || tk.Matches(a) {
		t.Fatalf("before: %+v, %v", a, err)
	}
	if err := windows.ApplyTask(ctx, c, tk, ""); err != nil {
		t.Fatal(err)
	}
	if a, err = windows.ReadTask(ctx, c, tk); err != nil || !tk.Matches(a) {
		t.Fatalf("after: %+v, %v", a, err)
	}
	if a.Actions[0].Arguments != tk.Arguments || a.Description != desc {
		t.Errorf("stored %q, %q", a.Actions[0].Arguments, a.Description)
	}
	if !runTask(t, c, tk, out) {
		t.Error("the task didn't run")
	}
	// Changes by hand are drift, and applying again puts them back.
	for what, change := range map[string]string{
		"disabled":  `Disable-ScheduledTask -TaskPath $A.path -TaskName $A.name | Out-Null`,
		"program":   `$t = Get-ScheduledTask -TaskPath $A.path -TaskName $A.name; $t.Actions[0].Execute = 'C:\Windows\System32\notepad.exe'; Set-ScheduledTask -InputObject $t | Out-Null`,
		"run level": `$t = Get-ScheduledTask -TaskPath $A.path -TaskName $A.name; $t.Principal.RunLevel = 'Highest'; Set-ScheduledTask -InputObject $t | Out-Null`,
	} {
		run(t, c, "param($A) "+change, map[string]any{"path": tk.Path, "name": tk.Name})
		if a, _ = windows.ReadTask(ctx, c, tk); tk.Matches(a) {
			t.Errorf("%s: drift matched", what)
		}
		if err := windows.ApplyTask(ctx, c, tk, ""); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if a, _ = windows.ReadTask(ctx, c, tk); !tk.Matches(a) {
			t.Errorf("%s: not put back", what)
		}
	}
	// The same task, user by SID, still matches.
	bySID := tk
	bySID.User = "S-1-5-18"
	if a, _ = windows.ReadTask(ctx, c, bySID); !bySID.Matches(a) {
		t.Error("SYSTEM by SID didn't match")
	}
	if err := windows.ApplyTaskRemove(ctx, c, tk.Path, tk.Name); err != nil {
		t.Fatal(err)
	}
	if a, _ = windows.ReadTask(ctx, c, tk); a.Exists {
		t.Error("remove left the task")
	}
	if err := windows.ApplyTaskRemove(ctx, c, tk.Path, tk.Name); err != nil {
		t.Errorf("removing it twice: %v", err)
	}
	if got := strings.TrimSpace(run(t, c, `Test-Path -LiteralPath (Join-Path $HOME 'c3mark')`, nil).Text); got != "False" {
		t.Error("a hostile value ran")
	}
}

// A task with high rights must not run something others can change.
func TestTaskRefusesWritablePrograms(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	// A new folder under C:\ inherits Modify for Authenticated Users on the
	// Azure image; the test makes sure of it either way.
	open := `C:\c3open-` + randHex(4)
	locked := `C:\c3locked-` + randHex(4)
	adds := `C:\c3adds-` + randHex(4)
	run(t, c, `param($A)
[void][IO.Directory]::CreateDirectory($A.open)
$acl = Get-Acl -LiteralPath $A.open
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(([Security.Principal.SecurityIdentifier]'S-1-5-11'), 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
Set-Acl -LiteralPath $A.open -AclObject $acl
[IO.File]::Copy('C:\Windows\System32\whoami.exe', (Join-Path $A.open 'prog.exe'))
# A folder only admins can write to, holding a file anyone can change.
$sec = New-Object Security.AccessControl.DirectorySecurity
$sec.SetAccessRuleProtection($true, $false)
foreach ($s in 'S-1-5-18', 'S-1-5-32-544') { $sec.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(([Security.Principal.SecurityIdentifier]$s), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))) }
$sec.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(([Security.Principal.SecurityIdentifier]'S-1-5-32-545'), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
[void][IO.Directory]::CreateDirectory($A.locked, $sec)
$f = Join-Path $A.locked 'prog.exe'
[IO.File]::Copy('C:\Windows\System32\whoami.exe', $f)
$fa = Get-Acl -LiteralPath $f
$fa.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(([Security.Principal.SecurityIdentifier]'S-1-5-32-545'), 'Write', 'Allow')))
Set-Acl -LiteralPath $f -AclObject $fa
# A folder where others may only add files: no swapping, but room for a DLL.
$sec.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(([Security.Principal.SecurityIdentifier]'S-1-5-32-545'), 'CreateFiles', 'None', 'None', 'Allow')))
[void][IO.Directory]::CreateDirectory($A.adds, $sec)
[IO.File]::Copy('C:\Windows\System32\whoami.exe', (Join-Path $A.adds 'prog.exe'))`, map[string]any{"open": open, "locked": locked, "adds": adds})
	t.Cleanup(func() {
		_, _ = ps.User(context.Background(), c, `param($A) foreach ($d in $A.open, $A.locked, $A.adds) { if ([IO.Directory]::Exists($d)) { [IO.Directory]::Delete($d, $true) } }`, map[string]any{"open": open, "locked": locked, "adds": adds}, time.Minute)
	})
	for name, tc := range map[string]struct {
		mod  func(*windows.Task)
		want string
	}{
		"SYSTEM, open folder":         {func(tk *windows.Task) { tk.Execute = open + `\prog.exe` }, "S-1-5-11 can"},
		"NETWORK SERVICE, open":       {func(tk *windows.Task) { tk.Execute, tk.User = open+`\prog.exe`, "NETWORK SERVICE" }, "S-1-5-11 can"},
		"SYSTEM, writable file":       {func(tk *windows.Task) { tk.Execute = locked + `\prog.exe` }, "can change"},
		"SYSTEM, open working folder": {func(tk *windows.Task) { tk.WorkingDirectory = open }, "S-1-5-11 can"},
		"SYSTEM, others add files":    {func(tk *windows.Task) { tk.Execute = adds + `\prog.exe` }, "can add or replace files"},
		"SYSTEM, missing program":     {func(tk *windows.Task) { tk.Execute = locked + `\none.exe` }, "doesn't exist"},
	} {
		tk := newTask(t, c)
		tc.mod(&tk)
		err := windows.ApplyTask(ctx, c, tk, "")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
		if a, _ := windows.ReadTask(ctx, c, tk); a.Exists {
			t.Errorf("%s: registered anyway", name)
		}
	}
	// Paths in arguments are checked like the program.
	run(t, c, `param($A) foreach ($f in 'job.bat', 'x.dll') { [IO.File]::WriteAllText((Join-Path $A.open $f), 'rem') }`, map[string]any{"open": open})
	for name, tc := range map[string]struct{ args, want string }{
		"script in an open folder":  {`/c ` + open + `\job.bat`, "S-1-5-11 can"},
		"quoted, with an option":    {`/c call "` + open + `\job.bat" --x`, "S-1-5-11 can"},
		"rundll32 entry point":      {open + `\x.dll,Entry`, "S-1-5-11 can"},
		"script on a share":         {`-File \\server\share\x.ps1`, "share"},
		"redirect into open folder": {`/c whoami >` + open + `\job.bat`, "S-1-5-11 can"},
		// The bypasses a review found in the first version of this check.
		"inside -Command text":   {`-Command "& ` + open + `\job.bat; whoami"`, "S-1-5-11 can"},
		"single-quoted":          {`-Command "& '` + open + `\job.bat'"`, "S-1-5-11 can"},
		"no extension":           {`/c ` + open + `\job`, "S-1-5-11 can"},
		"rundll32 with no .dll":  {open + `\x,Entry`, "S-1-5-11 can"},
		"forward slashes":        {`/c ` + strings.ReplaceAll(open, `\`, "/") + `/job.bat`, "S-1-5-11 can"},
		"environment variable":   {`/c %PUBLIC%\job`, "must not contain %"},
		"caret":                  {`/c job.b^at`, "must not contain %"},
		"relative from System32": {`/c ..\..\Users\Public\job`, "isn't a switch"},
		// The third review's cases.
		"rooted forward slash":     {`/Users/Public/evil.dll,Entry`, "isn't a switch"},
		"file URL":                 {`file:///C:/Users/Public/x.ps1`, "isn't a switch"},
		"drive-relative":           {`D:evil.dll,Entry`, "isn't a switch"},
		"second path in one quote": {`"C:\Windows\System32\cmd.exe /c \Users\Public\job.bat"`, "isn't a switch"},
		"not a fixed NTFS drive":   {`--config Z:\c3\x.json`, "fixed NTFS"},
		"public folder, missing":   {`/c C:\Users\Public\c3-` + randHex(4), "can"},
	} {
		tk := newTask(t, c)
		tk.Arguments = tc.args
		err := windows.ApplyTask(ctx, c, tk, "")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A renamed interpreter is still one, by the name Windows records in it.
	renamed := locked + `\tool.exe`
	run(t, c, `param($A) [IO.File]::Copy('C:\Windows\System32\cmd.exe', $A.f)`, map[string]any{"f": renamed})
	tkR := newTask(t, c)
	tkR.Execute, tkR.AllowInterpreter = renamed, false
	if err := windows.ApplyTask(ctx, c, tkR, ""); err == nil || !strings.Contains(err.Error(), "cmd.exe") {
		t.Errorf("renamed cmd.exe: %v", err)
	}
	tkR.AllowInterpreter = true
	if err := windows.ApplyTask(ctx, c, tkR, ""); err != nil {
		t.Errorf("renamed cmd.exe with allow_interpreter: %v", err)
	}
	// A script that doesn't exist yet, in a folder only administrators can
	// change, is fine: nobody else can put it there.
	tk0 := newTask(t, c)
	tk0.Arguments = `-File ` + locked + `\later.ps1`
	if err := windows.ApplyTask(ctx, c, tk0, ""); err != nil {
		t.Errorf("a script to come, in an admin-only folder: %v", err)
	}
	// An interpreter without the opt-in is refused before the host.
	tk1 := newTask(t, c)
	tk1.AllowInterpreter = false
	if err := windows.ApplyTask(ctx, c, tk1, ""); err == nil || !strings.Contains(err.Error(), "allow_interpreter") {
		t.Errorf("cmd.exe without allow_interpreter: %v", err)
	}
	// Every task is checked, at any run level and for any account: the
	// login's own limited task from the open folder is refused too.
	tk := newTask(t, c)
	tk.Execute, tk.User = open+`\prog.exe`, env(t, "CONN3X_WIN_USER")
	if err := windows.ApplyTask(ctx, c, tk, ""); err == nil {
		t.Error("a limited task from an open folder was registered")
	}
	// Plain arguments and a new output file are fine.
	tk = newTask(t, c)
	tk.Arguments = `/c echo "a b" > ` + tempDir(t, c) + `\out.txt`
	if err := windows.ApplyTask(ctx, c, tk, ""); err != nil {
		t.Errorf("ordinary arguments: %v", err)
	}
}

// A user given as a SID, and a service account spelled another way, match
// what Windows stores, with no drift.
func TestTaskUserForms(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	// S4U for another account is refused by Windows from a key session, so
	// this is the login itself, by SID.
	login := env(t, "CONN3X_WIN_USER")
	u, err := windows.ReadUser(ctx, c, login)
	if err != nil || u.SID == "" {
		t.Fatalf("%+v, %v", u, err)
	}
	for _, user := range []string{u.SID, `NT AUTHORITY\SYSTEM`, "S-1-5-18"} {
		tk := newTask(t, c)
		tk.User = user
		if err := windows.ApplyTask(ctx, c, tk, ""); err != nil {
			t.Fatalf("%s: %v", user, err)
		}
		a, err := windows.ReadTask(ctx, c, tk)
		if err != nil || !tk.Matches(a) {
			t.Errorf("%s: %+v, %v", user, a, err)
		}
	}
}

// With module, script block and 4688 command-line logging on, a task's
// password reaches no event and no file, and the task runs with it.
func TestTaskPasswordSentinel(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	user := accountName(t, c, "c3k")
	sentinel := "s3ntinel-Tk-" + randHex(6) + "Q"
	if err := windows.ApplyUser(ctx, c, windows.User{Name: user}, windows.ActualUser{}, &sentinel); err != nil {
		t.Fatal(err)
	}
	// Password logons need the batch right, which Administrators have.
	admins := windows.Group{Name: "Administrators", Members: []string{user}}
	ga, err := windows.ReadGroup(ctx, c, admins)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.ApplyGroup(ctx, c, admins, ga); err != nil {
		t.Fatal(err)
	}
	run(t, c, `$b = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
New-Item -Force -Path "$b\ModuleLogging\ModuleNames" | Out-Null
New-Item -Force -Path "$b\ScriptBlockLogging" | Out-Null
Set-ItemProperty -LiteralPath "$b\ModuleLogging" -Name EnableModuleLogging -Value 1
Set-ItemProperty -LiteralPath "$b\ModuleLogging\ModuleNames" -Name '*' -Value '*'
Set-ItemProperty -LiteralPath "$b\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1
$a = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -Force -Path $a | Out-Null
Set-ItemProperty -LiteralPath $a -Name ProcessCreationIncludeCmdLine_Enabled -Value 1
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

	// Somewhere only administrators can change, as paths in arguments are
	// checked; elevated, so this user's administrator rights can write there.
	out := tempDir(t, c) + `\c3pw-` + randHex(4) + ".txt"
	tk := newTask(t, c)
	tk.User, tk.HasPassword, tk.Highest = user, true, true
	tk.Arguments = "/c whoami > " + out
	if err := windows.ApplyTask(ctx, c, tk, "wrong-"+sentinel); err == nil {
		t.Error("Task Scheduler took a wrong password")
	} else if strings.Contains(err.Error(), sentinel) {
		t.Errorf("the password is in the error: %v", err)
	}
	if err := windows.ApplyTask(ctx, c, tk, sentinel); err != nil {
		t.Fatal(err)
	}
	if a, err := windows.ReadTask(ctx, c, tk); err != nil || !tk.Matches(a) {
		t.Fatalf("%+v, %v", a, err)
	}
	ran := runTask(t, c, tk, out)

	needles := []string{sentinel, b64(sentinel)}
	res := run(t, c, `param($A)
$from = [datetime]$A.since
$n = @{}; $hits = @()
foreach ($q in @(@{ LogName = 'Microsoft-Windows-PowerShell/Operational' }, @{ LogName = 'Windows PowerShell' }, @{ LogName = 'Security'; Id = 4688 }, @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational' })) {
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
	restore()
	res = run(t, c, `param($A)
$hits = @()
foreach ($d in @('C:\ProgramData\ssh\logs', 'C:\Windows\Temp', $env:TEMP, 'C:\Windows\System32\LogFiles', 'C:\Windows\System32\Tasks')) {
  foreach ($f in @(Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue)) {
    try { $text = [IO.File]::ReadAllText($f.FullName) } catch { continue }
    foreach ($w in $A.needles) { if ($text.Contains($w)) { $hits += $f.FullName } }
  }
}
"hits=$($hits -join ',')"`, map[string]any{"needles": needles})
	if got := strings.TrimSpace(res.Text); got != "hits=" {
		t.Errorf("a password is in a file: %s", got)
	}
	if !ran {
		t.Error("the task didn't run with its password, so this proves less")
	}
}

// TestTaskFlow is plan, apply, drift and removal through the binary, with the
// password in state as an HMAC only.
func TestTaskFlow(t *testing.T) {
	bin := os.Getenv("CONN3X_WIN_BIN")
	if bin == "" {
		t.Skip("CONN3X_WIN_BIN is not set")
	}
	c := connect(t)
	ctx := context.Background()
	user := accountName(t, c, "c3f")
	pw := "s3ntinel-Fl-" + randHex(6) + "Q"
	if err := windows.ApplyUser(ctx, c, windows.User{Name: user}, windows.ActualUser{}, &pw); err != nil {
		t.Fatal(err)
	}
	admins := windows.Group{Name: "Administrators", Members: []string{user}}
	ga, _ := windows.ReadGroup(ctx, c, admins)
	if err := windows.ApplyGroup(ctx, c, admins, ga); err != nil {
		t.Fatal(err)
	}
	tk := newTask(t, c)
	dir := t.TempDir()
	key := env(t, "CONN3X_WIN_KEY")
	if abs, err := filepath.Abs(key); err == nil {
		key = abs
	}
	write := func(steps string) {
		t.Helper()
		src := fmt.Sprintf(`
variable "pw" {
  type      = string
  ephemeral = true
}
circuit "win" {
  hosts = { vm = %[1]q }
  ssh {
    user             = %[2]q
    private_key_file = %[3]q
    host_key         = %[4]q
    become           = true
  }
  %[5]s
}
`, env(t, "CONN3X_WIN_HOST"), env(t, "CONN3X_WIN_USER"), key, env(t, "CONN3X_WIN_HOST_KEY"), steps)
		if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tool := func(args ...string) (string, int) {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "CONN3X_HMAC_KEY="+strings.Repeat("k", 32), "TF_VAR_pw="+pw)
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return string(out), ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return string(out), 0
	}
	plan := func(want int) {
		t.Helper()
		out, code := tool("plan", "-no-color", "-input=false", "-detailed-exitcode")
		if code != want {
			t.Fatalf("plan: exit %d, want %d\n%s", code, want, out)
		}
		if strings.Contains(out, pw) {
			t.Fatal("the password is in plan output")
		}
	}
	apply := func() {
		t.Helper()
		out, code := tool("apply", "-no-color", "-input=false", "-auto-approve")
		if code != 0 {
			t.Fatalf("apply: exit %d\n%s", code, out)
		}
		if strings.Contains(out, pw) {
			t.Fatal("the password is in apply output")
		}
	}
	write(fmt.Sprintf(`step "job" {
    windows_scheduled_task {
      name        = %q
      path        = %q
      execute     = %q
      arguments   = "/c exit 0"
      allow_interpreter = true
      user        = %q
      password_wo = var.pw

      trigger {
        type = "daily"
        at   = "2030-01-01T03:00:00"
      }
    }
  }`, tk.Name, tk.Path, cmdExe, user))
	if out, code := tool("init", "-no-color"); code != 0 {
		t.Fatal(out)
	}
	plan(2)
	apply()
	plan(0)
	state, _ := os.ReadFile(filepath.Join(dir, "terraform.tfstate"))
	if strings.Contains(string(state), pw) || !strings.Contains(string(state), "hmac-sha256:") {
		t.Error("state holds the password, or no HMAC of it")
	}
	run(t, c, `param($A) Disable-ScheduledTask -TaskPath $A.path -TaskName $A.name | Out-Null`, map[string]any{"path": tk.Path, "name": tk.Name})
	plan(2)
	apply()
	plan(0)
	write("")
	apply()
	if a, _ := windows.ReadTask(ctx, c, tk); a.Exists {
		t.Error("removing the step left the task")
	}
}

// What GetFullPath does with a short name and with a folder name ending in a
// space or a dot. On Server 2025 it leaves PROGRA~1 as it is and keeps the
// space, trimming only the dot, so the host refuses both forms itself rather
// than trusting a full-name comparison.
func TestPathForms(t *testing.T) {
	c := connect(t)
	res := run(t, c, `$short = (New-Object -ComObject Scripting.FileSystemObject).GetFolder('C:\Program Files').ShortPath + '\x'
"short=$short full=$([IO.Path]::GetFullPath($short))"
"space=$([IO.Path]::GetFullPath('C:\Windows \System32\cmd.exe'))"
"dot=$([IO.Path]::GetFullPath('C:\Windows.\System32\cmd.exe'))"`, nil)
	t.Log("\n" + res.Text)
	// Whatever GetFullPath does, these never reach a task.
	for _, args := range []string{`"C:\Windows \System32\cmd.exe"`, `C:\Windows.\System32\cmd.exe`, `C:\PROGRA~1\x.exe`} {
		if _, err := windows.ArgumentPaths(args); err == nil {
			t.Errorf("accepted %s", args)
		}
	}
	tk := newTask(t, c)
	tk.Execute = `C:\PROGRA~1\Windows NT\Accessories\wordpad.exe`
	if err := windows.ApplyTask(context.Background(), c, tk, ""); err == nil || !strings.Contains(err.Error(), "short name") {
		t.Errorf("short-name program: %v", err)
	}
}
