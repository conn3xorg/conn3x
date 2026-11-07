// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build windowshost

// Package windowshost tests Conn3x against a real Windows Server over SSH. It
// runs on GitHub's windows-2025 runner against loopback sshd, and by hand
// against an Azure VM:
//
//	CONN3X_WIN_HOST=1.2.3.4 CONN3X_WIN_USER=azadmin CONN3X_WIN_KEY=./admin \
//	CONN3X_WIN_HOST_KEY="$(cat hk.pub)" \
//	go test -tags windowshost -count=1 -v ./test/windows/
//
// CONN3X_WIN_REBOOT=1 adds the reboot tests, which a runner can't survive.
// CONN3X_WIN_BIN names a conn3x binary and adds the whole plan and apply flow.
// CONN3X_WIN_SOAK sets how many rounds of the stdin soak to run; 3 by default.
package windowshost

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func env(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set", name)
	}
	return v
}

func connect(t *testing.T) *ssh.Client {
	t.Helper()
	key, err := os.ReadFile(env(t, "CONN3X_WIN_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := ssh.DialWait(context.Background(), ssh.Config{
		Host: env(t, "CONN3X_WIN_HOST"), User: env(t, "CONN3X_WIN_USER"), PrivateKey: key, HostKey: env(t, "CONN3X_WIN_HOST_KEY"),
	}, 3*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// run runs test code on the host through the same path as a user's script.
func run(t *testing.T, c *ssh.Client, script string, args map[string]any) ps.Result {
	t.Helper()
	res, err := ps.User(context.Background(), c, script, args, 5*time.Minute)
	if err != nil {
		t.Fatalf("%v\nscript: %s", err, script)
	}
	return res
}

// tempDir makes a directory on the host and removes it afterwards.
func tempDir(t *testing.T, c *ssh.Client) string {
	t.Helper()
	res := run(t, c, `[IO.Directory]::CreateDirectory((Join-Path $env:TEMP ('conn3x-' + [guid]::NewGuid()))).FullName`, nil)
	dir := strings.TrimSpace(res.Text)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = ps.User(ctx, c, `param($A) Remove-Item -LiteralPath $A.dir -Recurse -Force`, map[string]any{"dir": dir}, time.Minute)
	})
	return dir
}

func TestFacts(t *testing.T) {
	f, err := windows.Gather(context.Background(), connect(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", f)
	if !strings.HasPrefix(f.Version, "10.0.") || f.Release == "" || f.Arch != "x86_64" || f.CPUs < 1 || f.MemoryMB < 512 ||
		f.Hostname == "" || !strings.HasPrefix(f.PowerShell, "5.1") || f.Edition == "" || f.InstallationType == "" ||
		!strings.HasSuffix(f.Version, "."+f.Build) || f.UBR < 1 {
		t.Errorf("implausible facts: %+v", f)
	}
	if f.IPv4 == "" {
		t.Error("no IPv4 address from the default route")
	}
	if !f.Elevated {
		t.Error("the administrator's key login isn't elevated")
	}
}

func TestBootIDIsStableWithinABoot(t *testing.T) {
	c := connect(t)
	a, err := windows.BootID(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		b, err := windows.BootID(context.Background(), c)
		if err != nil || b != a {
			t.Fatalf("boot id moved from %q to %q: %v", a, b, err)
		}
	}
}

// A POSIX module on Windows gets told so, whichever shell sshd runs.
func TestPosixCommandGetsAClearError(t *testing.T) {
	_, err := connect(t).Run(context.Background(), "true", nil)
	if !errors.Is(err, ssh.ErrWindowsHost) {
		t.Fatalf("err = %v", err)
	}
	t.Log(err)
}

func TestOutcomes(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	if _, err := ps.User(ctx, c, `throw 'boom-sentinel'`, nil, time.Minute); err == nil || !strings.Contains(err.Error(), "boom-sentinel") {
		t.Errorf("throw: err = %v", err)
	}
	if _, err := ps.User(ctx, c, `Get-Item -LiteralPath 'C:\does\not\exist'`, nil, time.Minute); err == nil {
		t.Error("a failing cmdlet didn't fail")
	}
	for _, code := range []int{0, 7} {
		_, err := ps.User(ctx, c, fmt.Sprintf("exit %d", code), nil, time.Minute)
		if err == nil || !strings.Contains(err.Error(), "called exit") {
			t.Errorf("exit %d: err = %v", code, err)
		}
	}
	res := run(t, c, `cmd.exe /c exit 3010`, nil)
	if res.ExitCode != 3010 {
		t.Errorf("native exit code = %d", res.ExitCode)
	}
	if _, err := windows.RunScript(ctx, c, `cmd.exe /c exit 3010`, nil, nil, time.Minute); err == nil || !strings.Contains(err.Error(), "3010") {
		t.Errorf("RunScript: err = %v", err)
	}
	if res := run(t, c, `Write-Output 'one'; Write-Progress -Activity x; [Console]::Error.WriteLine('to stderr'); Write-Output 'two'`, nil); !strings.Contains(res.Text, "one") || !strings.Contains(res.Text, "two") {
		t.Errorf("stray output broke the result: %+v", res)
	}
	if res := run(t, c, `$false`, nil); string(res.Value) != "false" {
		t.Errorf("value = %q", res.Value)
	}
}

// hostile is the table of values no module may ever treat as anything but text.
var hostile = map[string]string{
	"single quote":   `'; Remove-Item C:\marker; '`,
	"double quote":   `"; Remove-Item C:\marker; "`,
	"subexpression":  `$(New-Item C:\marker)`,
	"variable":       `$env:WINDIR`,
	"backtick":       "a`nb`$c`",
	"smart quotes":   "\u2018x\u2019 \u201cy\u201d",
	"percent":        `%PATH%`,
	"NUL":            "a\x00b",
	"newlines":       "a\r\nb\nc",
	"trailing slash": `C:\dir\`,
	"emoji":          "\U0001F680",
	"pipe":           `a | b & c ; d > e`,
	"wildcards":      `C:\*[a-z]?`,
	"64 KiB":         strings.Repeat("x", 64<<10),
	// Valid as a Windows account name, and code anywhere it isn't a literal.
	"account name": `$(md c3mark)'`,
	"account list": `a'; Add-LocalGroupMember Administrators -Member Guest; '`,
	"sid":          `S-1-5-32-544'; $(md c3mark)`,
}

// Every value comes back byte for byte through the only way in.
func TestHostileValuesRoundTrip(t *testing.T) {
	c := connect(t)
	for name, v := range hostile {
		t.Run(name, func(t *testing.T) {
			var got string
			back, err := ps.Read(context.Background(), c, ps.Script{Name: "read_test.ps1", Body: `param($A) $A.value`}, map[string]any{"value": v})
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(back.Value, &got); err != nil {
				t.Fatalf("%q: %v", back.Value, err)
			}
			if got != v {
				t.Fatalf("sent %q, got %q", v, got)
			}
		})
	}
}

// Through the real scripts: paths with hostile text stay paths, and nothing runs.
func TestHostileValuesThroughModuleScripts(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	dir := tempDir(t, c)
	marker := dir + `\marker`
	literal := dir + `\[literal] $(x) 'q'.txt`
	run(t, c, `param($A) [IO.File]::WriteAllText($A.p, 'x')`, map[string]any{"p": literal})

	if ok, err := (windows.WaitFor{Path: literal}).Ready(ctx, c); err != nil || !ok {
		t.Errorf("Ready on a path with wildcards and quotes = %v, %v", ok, err)
	}
	if ok, err := windows.Satisfied(ctx, c, windows.Guards{Creates: literal}, nil); err != nil || !ok {
		t.Errorf("creates on that path = %v, %v", ok, err)
	}
	// Wildcards must match nothing but themselves.
	if ok, err := windows.Satisfied(ctx, c, windows.Guards{Creates: dir + `\*`}, nil); err != nil || ok {
		t.Errorf("creates with a wildcard = %v, %v", ok, err)
	}
	for name, v := range hostile {
		if strings.ContainsRune(v, 0) || strings.Contains(v, "\n") || len(v) > 1000 {
			continue // validation refuses these before they reach a host
		}
		attack := strings.ReplaceAll(v, `C:\marker`, marker)
		p := `C:\` + attack
		if ok, err := (windows.WaitFor{Path: p}).Ready(ctx, c); err != nil {
			t.Logf("%s: Ready error is fine: %v", name, err)
		} else if ok && name != "wildcards" && name != "trailing slash" {
			t.Errorf("%s: Ready = true for %q", name, p)
		}
		if _, err := windows.Satisfied(ctx, c, windows.Guards{Removes: p}, nil); err != nil {
			t.Logf("%s: guard error is fine: %v", name, err)
		}
		if ok, _ := (windows.WaitFor{Service: attack}).Ready(ctx, c); ok {
			t.Errorf("%s: a service named %q counted as running", name, attack)
		}
	}
	res := run(t, c, `param($A) Test-Path -LiteralPath $A.m`, map[string]any{"m": marker})
	if strings.TrimSpace(res.Text) != "False" {
		t.Fatal("a hostile value ran: the marker exists")
	}
}

// A secret never comes back in anything that reaches state or logs.
func TestSecretsAreBlanked(t *testing.T) {
	c := connect(t)
	const secret = "s3ntinel-hunter2"
	args := map[string]any{"pw": secret}
	out, err := windows.RunScript(context.Background(), c, `param($A) Write-Output "out $($A.pw)"; [Console]::Error.WriteLine("err $($A.pw)")`, args, []string{secret}, time.Minute)
	if err != nil || strings.Contains(out.Stdout+out.Stderr, secret) || !strings.Contains(out.Stdout, "out ") {
		t.Errorf("out %+v, err %v", out, err)
	}
	_, err = windows.RunScript(context.Background(), c, `param($A) throw "bad $($A.pw)"`, args, []string{secret}, time.Minute)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("err = %v", err)
	}
}

// A deadline ends the run and the process tree, and the connection survives.
func TestDeadlineStopsTheTree(t *testing.T) {
	c := connect(t)
	dir := tempDir(t, c)
	start := time.Now()
	_, err := ps.User(context.Background(), c, `param($A) Set-Content -LiteralPath $A.p -Value $PID; ping.exe -n 120 127.0.0.1`, map[string]any{"p": dir + `\pid`}, 6*time.Second)
	var noResult *ps.NoResultError
	if !errors.As(err, &noResult) || time.Since(start) > 30*time.Second {
		t.Fatalf("after %s: err = %v", time.Since(start), err)
	}
	if !c.Alive() {
		t.Fatal("the connection died")
	}
	time.Sleep(2 * time.Second)
	res := run(t, c, `param($A) [bool](Get-Process -Id ([int](Get-Content -LiteralPath $A.p)) -ErrorAction SilentlyContinue)`, map[string]any{"p": dir + `\pid`})
	if strings.TrimSpace(res.Text) != "False" {
		t.Error("PowerShell is still running after the deadline")
	}
}

// The stdin path hangs at some sizes if read any way but one. Keep it honest.
func TestStdinSoak(t *testing.T) {
	c := connect(t)
	rounds := 3
	if v := os.Getenv("CONN3X_WIN_SOAK"); v != "" {
		var err error
		if rounds, err = strconv.Atoi(v); err != nil {
			t.Fatal(err)
		}
	}
	sizes := []int{1 << 10, 8 << 10, 16 << 10, 64 << 10, 256 << 10, 1 << 20, 3 << 20}
	var slowest time.Duration
	for r := range rounds {
		for _, size := range sizes {
			start := time.Now()
			res, err := ps.User(context.Background(), c, `param($A) $A.value.Length`, map[string]any{"value": strings.Repeat("s", size)}, time.Minute)
			if err != nil {
				t.Fatalf("round %d, %d bytes: %v", r, size, err)
			}
			if got := strings.TrimSpace(res.Text); got != strconv.Itoa(size) {
				t.Fatalf("round %d: sent %d bytes, script saw %s", r, size, got)
			}
			slowest = max(slowest, time.Since(start))
		}
	}
	t.Logf("%d runs, slowest %s", rounds*len(sizes), slowest)
	if !c.Alive() {
		t.Fatal("the connection stopped answering")
	}
}

// snapshotScript is what a read must leave alone. Service status isn't in it,
// as Windows starts and stops demand-start services by itself, and neither is
// BITS, whose start type Windows changes for itself in the minutes after a boot.
const snapshotScript = `param($A)
$o = [ordered]@{}
Get-Service | Where-Object Name -ne 'BITS' | Sort-Object Name | ForEach-Object { $o["service " + $_.Name] = [string]$_.StartType }
Get-WindowsFeature | Where-Object Installed | ForEach-Object { $o["feature " + $_.Name] = 'installed' }
Get-ScheduledTask | ForEach-Object { $o["task " + $_.TaskPath + $_.TaskName] = (($_.Actions | ForEach-Object { [string]$_.Execute + ' ' + [string]$_.Arguments }) -join ';') }
foreach ($k in 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem', 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\OpenSSH') {
  if (Test-Path -LiteralPath $k) { (Get-ItemProperty -LiteralPath $k).PSObject.Properties | Where-Object Name -notlike 'PS*' | ForEach-Object { $o["reg $k " + $_.Name] = [string]$_.Value } }
}
Get-ChildItem -LiteralPath 'C:\ProgramData\ssh' -Filter 'ssh_host*' | ForEach-Object { $o["hash " + $_.Name] = (Get-FileHash -LiteralPath $_.FullName).Hash }
if ($A.dir) { Get-ChildItem -LiteralPath $A.dir -Recurse -File | ForEach-Object { $o["hash " + $_.FullName] = (Get-FileHash -LiteralPath $_.FullName).Hash } }
$o.GetEnumerator() | ForEach-Object { $_.Key + " = " + $_.Value }`

func snapshot(t *testing.T, c *ssh.Client, dir string) []string {
	t.Helper()
	return strings.Split(strings.TrimSpace(run(t, c, snapshotScript, map[string]any{"dir": dir}).Text), "\n")
}

func compare(t *testing.T, before, after []string) {
	t.Helper()
	if slices.Equal(before, after) {
		t.Logf("snapshot unchanged: %d entries", len(before))
		return
	}
	for _, l := range before {
		if !slices.Contains(after, l) {
			t.Errorf("gone:  %s", l)
		}
	}
	for _, l := range after {
		if !slices.Contains(before, l) {
			t.Errorf("new:   %s", l)
		}
	}
}

// Every read script, run over and over, changes nothing.
func TestReadsChangeNothing(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	dir := tempDir(t, c)
	before := snapshot(t, c, dir)
	for range 3 {
		if _, err := windows.Gather(ctx, c); err != nil {
			t.Fatal(err)
		}
		if _, err := windows.BootID(ctx, c); err != nil {
			t.Fatal(err)
		}
		if _, err := windows.PendingReboot(ctx, c); err != nil {
			t.Fatal(err)
		}
		if _, err := windows.Elevated(ctx, c); err != nil {
			t.Fatal(err)
		}
		for _, w := range []windows.WaitFor{{Path: dir + `\none`}, {Service: "sshd"}, {Port: 22}} {
			if _, err := w.Ready(ctx, c); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := windows.Satisfied(ctx, c, windows.Guards{Creates: dir + `\a`, Removes: dir + `\b`}, nil); err != nil {
			t.Fatal(err)
		}
	}
	compare(t, before, snapshot(t, c, dir))
}

func TestWaitForChecks(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	for w, want := range map[windows.WaitFor]bool{
		{Service: "sshd"}:            true,
		{Service: "no-such-service"}: false,
		{Port: 22}:                   true,
		{Port: 1}:                    false,
		{Path: `C:\Windows`}:         true,
		{Path: `C:\no\such\path`}:    false,
	} {
		if err := w.Validate(); err != nil {
			t.Errorf("%v: %v", w, err)
		}
		if ok, err := w.Ready(ctx, c); err != nil || ok != want {
			t.Errorf("%v: Ready = %v, %v; want %v", w, ok, err, want)
		}
	}
}

func TestUnlessGuard(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	for script, want := range map[string]bool{
		`Test-Path -LiteralPath 'C:\Windows'`:      true,
		`Test-Path -LiteralPath 'C:\no\such\path'`: false,
		`throw 'no'`:             false,
		`cmd.exe /c exit 1`:      false,
		`cmd.exe /c exit 0`:      true,
		`param($A) $A.x -eq 'y'`: true,
		`param($A) $A.x -eq 'z'`: false,
	} {
		if ok, err := windows.Satisfied(ctx, c, windows.Guards{Unless: script}, map[string]any{"x": "y"}); err != nil || ok != want {
			t.Errorf("%s: %v, %v; want %v", script, ok, err, want)
		}
	}
}

func TestReboot(t *testing.T) {
	if os.Getenv("CONN3X_WIN_REBOOT") == "" {
		t.Skip("CONN3X_WIN_REBOOT is not set")
	}
	c := connect(t)
	ctx := context.Background()
	before, err := windows.BootID(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := windows.ApplyReboot(ctx, c); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 4*time.Second {
		t.Errorf("scheduling took %s; it has to return before the connection drops", took)
	}
	c.Close()
	for time.Since(start) < 10*time.Minute {
		time.Sleep(5 * time.Second)
		c2 := connect(t)
		short, cancel := context.WithTimeout(ctx, 30*time.Second)
		now, err := windows.BootID(short, c2)
		cancel()
		if err == nil && now != before {
			t.Logf("back after %s: boot id %s to %s", time.Since(start).Round(time.Second), before, now)
			return
		}
	}
	t.Fatal("the host did not come back")
}

// TestPlanAndApply is the whole flow through the conn3x binary.
func TestPlanAndApply(t *testing.T) {
	bin := os.Getenv("CONN3X_WIN_BIN")
	if bin == "" {
		t.Skip("CONN3X_WIN_BIN is not set")
	}
	c := connect(t)
	remote := tempDir(t, c)
	dir := t.TempDir()
	host, user, key, hostKey := env(t, "CONN3X_WIN_HOST"), env(t, "CONN3X_WIN_USER"), env(t, "CONN3X_WIN_KEY"), env(t, "CONN3X_WIN_HOST_KEY")
	if abs, err := filepath.Abs(key); err == nil {
		key = abs
	}
	reboot := ""
	if os.Getenv("CONN3X_WIN_REBOOT") != "" {
		reboot = `
    step "restart" {
      windows_reboot {
        triggers = { script = "1" }
      }
    }
    step "restart_if_needed" {
      windows_reboot {
        only_if_pending = true
      }
    }`
	}
	marker, secretFile := remote+`\marker.txt`, remote+`\secret.txt`
	acct, grp := accountName(t, c, "c3p"), accountName(t, c, "c3q")
	write := func(extraData string) {
		t.Helper()
		src := fmt.Sprintf(`
variable "secret" {
  type      = string
  ephemeral = true
  default   = "s3ntinel-p1-value"
}
data "conn3x_host" "win" {
  %[1]s
  ssh {
    host             = %[2]q
    user             = %[3]q
    private_key_file = %[4]q
    host_key         = %[5]q
  }
}
output "family" { value = data.conn3x_host.win.os_family }
output "windows" { value = data.conn3x_host.win.windows }
circuit "win" {
  hosts = { vm = %[2]q }
  ssh {
    user             = %[3]q
    private_key_file = %[4]q
    host_key         = %[5]q
    become           = true
  }
  step "write" {
    windows_powershell {
      script  = "param($A) Set-Content -LiteralPath $A.path -Value $A.value; 'wrote'"
      args    = { path = %[6]q, value = "it's $(fine) %%PATH%%" }
      creates = %[6]q
    }
  }
  step "secret" {
    windows_powershell {
      script  = "param($A) Set-Content -LiteralPath $A.path -Value $A.pw; $A.pw"
      args    = { path = %[7]q }
      args_wo = { pw = var.secret }
      creates = %[7]q
    }
  }
  step "sshd_up" {
    windows_wait_for {
      service = "sshd"
    }
  }
  step "port_up" {
    windows_wait_for {
      port = 22
    }
  }
  step "app_user" {
    windows_user {
      name        = %[9]q
      description = "Conn3x test"
      password_wo = var.secret
      on_remove   = "delete"
    }
  }
  step "app_group" {
    windows_group {
      name      = %[10]q
      members   = [%[9]q]
      on_remove = "delete"
    }
  }%[8]s
}
`, extraData, host, user, key, hostKey, marker, secretFile, reboot, acct, grp)
		if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tool := func(args ...string) (string, int) {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "CONN3X_HMAC_KEY="+strings.Repeat("k", 32))
		out, err := cmd.CombinedOutput()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return string(out), code
	}
	must := func(args ...string) string {
		t.Helper()
		out, code := tool(args...)
		if code != 0 {
			t.Fatalf("conn3x %v: exit %d\n%s", args, code, out)
		}
		return out
	}

	// Without allow_windows the host is refused at plan.
	write("")
	must("init", "-no-color")
	if out, code := tool("plan", "-no-color", "-input=false"); code == 0 || !strings.Contains(out, "is a Windows host") {
		t.Fatalf("plan without allow_windows: exit %d\n%s", code, out)
	}

	write("allow_windows = true")
	before := snapshot(t, c, remote)
	out, code := tool("plan", "-no-color", "-input=false", "-detailed-exitcode", "-out=tfplan")
	if code != 2 {
		t.Fatalf("first plan: exit %d\n%s", code, out)
	}
	if strings.Contains(out, "s3ntinel-p1-value") {
		t.Error("the secret is in the plan output")
	}
	compare(t, before, snapshot(t, c, remote))

	out = must("apply", "-no-color", "-input=false", "tfplan")
	t.Logf("first apply:\n%s", out)
	c = connect(t) // the apply may have rebooted the host
	if strings.Contains(out, "s3ntinel-p1-value") {
		t.Error("the secret is in the apply output")
	}
	if got := run(t, c, `param($A) Get-Content -LiteralPath $A.p -Raw`, map[string]any{"p": marker}).Text; !strings.Contains(got, `it's $(fine) %PATH%`) {
		t.Errorf("the host holds %q", got)
	}
	if got := run(t, c, `param($A) Get-Content -LiteralPath $A.p -Raw`, map[string]any{"p": secretFile}).Text; !strings.Contains(got, "s3ntinel-p1-value") {
		t.Errorf("the secret file holds %q", got)
	}
	state, err := os.ReadFile(filepath.Join(dir, "terraform.tfstate"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state), "s3ntinel-p1-value") {
		t.Error("the secret is in state")
	}
	if !strings.Contains(string(state), "hmac-sha256:") {
		t.Error("state has no HMAC of the secret")
	}
	if !passwordWorks(t, c, acct, "s3ntinel-p1-value") {
		t.Error("windows_user didn't set the password")
	}
	if g, err := windows.ReadGroup(context.Background(), c, windows.Group{Name: grp, Members: []string{acct}}); err != nil || len(g.Members) != 1 {
		t.Errorf("group %+v, %v", g, err)
	}
	fam := strings.TrimSpace(must("output", "-raw", "family"))
	if fam != "windows" {
		t.Errorf("os_family = %q", fam)
	}
	t.Logf("windows facts: %s", must("output", "-json", "windows"))

	// A second plan is clean and changes nothing on the host.
	before = snapshot(t, c, remote)
	if out, code := tool("plan", "-no-color", "-input=false", "-detailed-exitcode"); code != 0 {
		t.Errorf("second plan: exit %d\n%s", code, out)
	}
	compare(t, before, snapshot(t, c, remote))

	// Remove what the guard watches: plan sees it, apply brings it back.
	run(t, c, `param($A) Remove-Item -LiteralPath $A.p`, map[string]any{"p": marker})
	if out, code := tool("plan", "-no-color", "-input=false", "-detailed-exitcode"); code != 2 {
		t.Errorf("plan after removing the guarded file: exit %d\n%s", code, out)
	}
	must("apply", "-no-color", "-input=false", "-auto-approve")
	if got := strings.TrimSpace(run(t, c, `param($A) Test-Path -LiteralPath $A.p`, map[string]any{"p": marker}).Text); got != "True" {
		t.Errorf("reapply didn't bring it back: %s", got)
	}

	// A user changed by hand shows as drift, and apply puts it back.
	run(t, c, `param($A) Set-LocalUser -Name $A.n -Description 'changed by hand'`, map[string]any{"n": acct})
	if out, code := tool("plan", "-no-color", "-input=false", "-detailed-exitcode"); code != 2 || !strings.Contains(out, "app_user") {
		t.Errorf("plan after changing the user: exit %d\n%s", code, out)
	}
	must("apply", "-no-color", "-input=false", "-auto-approve")
	if out, code := tool("plan", "-no-color", "-input=false", "-detailed-exitcode"); code != 0 {
		t.Errorf("plan after putting the user back: exit %d\n%s", code, out)
	}

	// A user deleted by hand comes back with its password, not without one.
	run(t, c, `param($A) Remove-LocalUser -Name $A.n`, map[string]any{"n": acct})
	if out, code := tool("plan", "-no-color", "-input=false", "-detailed-exitcode"); code != 2 {
		t.Errorf("plan after deleting the user: exit %d\n%s", code, out)
	}
	must("apply", "-no-color", "-input=false", "-auto-approve")
	if !passwordWorks(t, c, acct, "s3ntinel-p1-value") {
		t.Error("the user came back without its password")
	}

	// A name that changes only in case is the same account: updated, not
	// deleted and made again with a new SID.
	sidBefore, _ := windows.ReadUser(context.Background(), c, acct)
	acct, grp = strings.ToUpper(acct), strings.ToUpper(grp)
	write("allow_windows = true")
	if out, code := tool("plan", "-no-color", "-input=false", "-detailed-exitcode"); code != 2 || strings.Contains(out, "must be replaced") || !strings.Contains(out, "0 to destroy") {
		t.Errorf("plan after a case change: exit %d\n%s", code, out)
	}
	must("apply", "-no-color", "-input=false", "-auto-approve")
	if after, _ := windows.ReadUser(context.Background(), c, acct); after.SID != sidBefore.SID || after.SID == "" {
		t.Errorf("SID %s became %s", sidBefore.SID, after.SID)
	}
	if out, code := tool("plan", "-no-color", "-input=false", "-detailed-exitcode"); code != 0 {
		t.Errorf("plan after the case change: exit %d\n%s", code, out)
	}

	if os.Getenv("CONN3X_WIN_REBOOT") != "" {
		// A reboot Windows wants, which a failed run would have missed.
		run(t, c, `New-Item -Force -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' | Out-Null`, nil)
		out, code := tool("plan", "-no-color", "-input=false", "-detailed-exitcode")
		if code != 2 || !strings.Contains(out, "restart_if_needed") {
			t.Errorf("plan with a pending reboot: exit %d\n%s", code, out)
		}
		bootBefore, _ := windows.BootID(context.Background(), c)
		out = must("apply", "-no-color", "-input=false", "-auto-approve")
		t.Logf("pending apply:\n%s", out)
		c2 := connect(t)
		bootAfter, err := windows.BootID(context.Background(), c2)
		if err != nil || bootAfter == bootBefore {
			t.Errorf("boot id %s to %s: %v", bootBefore, bootAfter, err)
		}
		run(t, c2, `Remove-Item -Force -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'`, nil)
		must("apply", "-no-color", "-input=false", "-auto-approve")
		if out, code := tool("plan", "-no-color", "-input=false", "-detailed-exitcode"); code != 0 {
			t.Errorf("plan after the reboot: exit %d\n%s", code, out)
		}
	}

	// A new password, with Tofu's most detailed logging on: the plan shows a
	// change, the log never shows the password, and the host has it. It goes
	// in through the environment: Tofu's trace log prints its command line.
	const next = "s3ntinel-p3-trace"
	t.Setenv("TF_VAR_secret", next)
	t.Setenv("TF_LOG", "trace")
	out, code = tool("plan", "-no-color", "-input=false", "-detailed-exitcode")
	if code != 2 || !strings.Contains(out, "password_hmac") {
		t.Errorf("plan with a new password: exit %d", code)
	}
	trace := out + must("apply", "-no-color", "-input=false", "-auto-approve")
	t.Setenv("TF_LOG", "")
	if !strings.Contains(trace, "[TRACE]") {
		t.Error("no trace logging, so this proves nothing")
	}
	if strings.Contains(trace, next) || strings.Contains(trace, b64(next)) {
		t.Error("the password is in Tofu's trace log")
	}
	if state, _ := os.ReadFile(filepath.Join(dir, "terraform.tfstate")); strings.Contains(string(state), next) {
		t.Error("the new password is in state")
	}
	c = connect(t) // the host may have rebooted since
	if !passwordWorks(t, c, acct, next) {
		t.Error("the new password wasn't set")
	}
	if out, code := tool("plan", "-no-color", "-input=false", "-detailed-exitcode"); code != 0 {
		t.Errorf("plan with the same password: exit %d\n%s", code, out)
	}
}

// fileText is a file's bytes on the host, as base64.
func fileText(t *testing.T, c *ssh.Client, p string) string {
	t.Helper()
	return run(t, c, `param($A) [Convert]::ToBase64String([IO.File]::ReadAllBytes($A.p))`, map[string]any{"p": p}).Text
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func sddl(t *testing.T, c *ssh.Client, p string) string {
	t.Helper()
	return strings.TrimSpace(run(t, c, `param($A) (Get-Acl -LiteralPath $A.p).Sddl`, map[string]any{"p": p}).Text)
}

// noTemp fails if a write left anything behind.
func noTemp(t *testing.T, c *ssh.Client, dir string) {
	t.Helper()
	if got := strings.TrimSpace(run(t, c, `param($A) @(Get-ChildItem -LiteralPath $A.d -Force -Filter '.conn3x-*').Count`, map[string]any{"d": dir}).Text); got != "0" {
		t.Errorf("%s temp files left in %s", got, dir)
	}
}

func TestFileBytesExactly(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	dir := tempDir(t, c)
	for name, content := range map[string]string{
		"crlf":   "a\r\nb\nc\r",
		"zero":   "a\x00b",
		"quotes": `'; $(x) "` + "`",
		"utf8":   "\u2018\U0001F680",
		"empty":  "",
		"2 MiB":  strings.Repeat("z", windows.MaxContent),
	} {
		p := dir + `\` + strings.ReplaceAll(name, " ", "_")
		if err := windows.ApplyFile(ctx, c, p, []byte(content), nil, nil); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := strings.TrimSpace(fileText(t, c, p)); got != b64(content) {
			t.Errorf("%s: bytes differ", name)
		}
		s, err := windows.ReadPath(ctx, c, p, nil, true)
		if err != nil || s.Kind != "file" {
			t.Fatalf("%s: %+v, %v", name, s, err)
		}
		sum := sha256.Sum256([]byte(content))
		if s.SHA256 != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: sha256 %s", name, s.SHA256)
		}
	}
	noTemp(t, c, dir)
}

func TestFileHostilePath(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	dir := tempDir(t, c)
	marker := dir + `\marker`
	for _, name := range []string{
		`[literal]`, `$(New-Item 'x')`, `it's`, "back`tick", `%PATH%`, `a;b&c`, "\u2018smart\u2019",
	} {
		p, err := windows.CleanLocalPath("path", dir+`\`+name)
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		if err := windows.ApplyFile(ctx, c, p, []byte("x"), nil, nil); err != nil {
			t.Errorf("%q: %v", name, err)
			continue
		}
		s, err := windows.ReadPath(ctx, c, p, nil, true)
		if err != nil || s.Kind != "file" {
			t.Errorf("%q read back: %+v, %v", name, s, err)
		}
		if err := windows.ApplyDirectory(ctx, c, p+"-dir", nil); err != nil {
			t.Errorf("%q as a folder: %v", name, err)
		}
	}
	got := run(t, c, `param($A) Test-Path -LiteralPath $A.m; @(Get-ChildItem -LiteralPath $A.d -Force).Count`, map[string]any{"m": marker, "d": dir}).Text
	if strings.Contains(got, "True") {
		t.Error("a hostile name ran")
	}
	if want := fmt.Sprint(7 * 2); !strings.Contains(got, want) {
		t.Errorf("expected %s entries, one per name and kind: %s", want, got)
	}
}

// mklinks makes a symlink, a junction and a hard link beside a protected target.
func mklinks(t *testing.T, c *ssh.Client, dir string) (target, targetDir string) {
	t.Helper()
	target, targetDir = dir+`\target.txt`, dir+`\target-dir`
	run(t, c, `param($A)
[IO.File]::WriteAllText($A.target, 'original')
[void][IO.Directory]::CreateDirectory($A.targetDir)
[IO.File]::WriteAllText($A.targetDir + '\inside.txt', 'inside')
$d = $A.dir
& cmd.exe /c mklink "$d\sym.txt" "$($A.target)" | Out-Null
if ($LASTEXITCODE) { throw 'mklink' }
& cmd.exe /c mklink /J "$d\junction" "$($A.targetDir)" | Out-Null
if ($LASTEXITCODE) { throw 'mklink /J' }
& cmd.exe /c mklink /H "$d\hard.txt" "$($A.target)" | Out-Null
if ($LASTEXITCODE) { throw 'mklink /H' }
$global:LASTEXITCODE = 0`, map[string]any{"target": target, "targetDir": targetDir, "dir": dir})
	return target, targetDir
}

// Nothing writes through a link: not at the path, not on the way to it.
func TestWritesDontFollowLinks(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	dir := tempDir(t, c)
	target, targetDir := mklinks(t, c, dir)
	wantText := fileText(t, c, target)
	wantInside := fileText(t, c, targetDir+`\inside.txt`)
	sddlTarget, sddlDir := sddl(t, c, target), sddl(t, c, targetDir)
	users := []windows.Entry{{Principal: "S-1-5-32-545", Rights: []string{"Modify"}}}

	for name, err := range map[string]error{
		"file over a symlink":      windows.ApplyFile(ctx, c, dir+`\sym.txt`, []byte("evil"), nil, nil),
		"file over a hard link":    windows.ApplyFile(ctx, c, dir+`\hard.txt`, []byte("evil"), nil, nil),
		"file through a junction":  windows.ApplyFile(ctx, c, dir+`\junction\inside.txt`, []byte("evil"), nil, nil),
		"new file via a junction":  windows.ApplyFile(ctx, c, dir+`\junction\new.txt`, []byte("evil"), nil, nil),
		"folder over a junction":   windows.ApplyDirectory(ctx, c, dir+`\junction`, users),
		"folder via a junction":    windows.ApplyDirectory(ctx, c, dir+`\junction\sub`, nil),
		"rules on a symlink":       windows.ApplyACL(ctx, c, windows.ACL{Path: dir + `\sym.txt`, Entries: users}, false),
		"rules on a hard link":     windows.ApplyACL(ctx, c, windows.ACL{Path: dir + `\hard.txt`, Entries: users}, false),
		"rules on a junction":      windows.ApplyACL(ctx, c, windows.ACL{Path: dir + `\junction`, Entries: users}, true),
		"rules through a junction": windows.ApplyACL(ctx, c, windows.ACL{Path: dir + `\junction\inside.txt`, Entries: users}, false),
	} {
		if err == nil {
			t.Errorf("%s: wasn't refused", name)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
	if fileText(t, c, target) != wantText || fileText(t, c, targetDir+`\inside.txt`) != wantInside {
		t.Error("a target's content changed through a link")
	}
	if got := strings.TrimSpace(run(t, c, `param($A) Test-Path -LiteralPath $A.p`, map[string]any{"p": targetDir + `\new.txt`}).Text); got != "False" {
		t.Error("a new file landed behind the junction")
	}
	if got := strings.TrimSpace(run(t, c, `param($A) Test-Path -LiteralPath $A.p`, map[string]any{"p": targetDir + `\sub`}).Text); got != "False" {
		t.Error("a new folder landed behind the junction")
	}
	if sddl(t, c, target) != sddlTarget || sddl(t, c, targetDir) != sddlDir {
		t.Error("a target's rules changed through a link")
	}
	// Reads tell the truth about what's there.
	if s, err := windows.ReadPath(ctx, c, dir+`\sym.txt`, nil, true); err != nil || s.Kind != "link" || s.SHA256 != "" {
		t.Errorf("symlink read: %+v, %v", s, err)
	}
	if s, err := windows.ReadPath(ctx, c, dir+`\junction\inside.txt`, nil, true); err != nil || s.LinkOnWay == "" {
		t.Errorf("path through a junction read: %+v, %v", s, err)
	}
	noTemp(t, c, dir)
	noTemp(t, c, targetDir)
}

// Rules set on a folder reach what's inside, but not what a junction inside points to.
func TestRulesStopAtALinkInside(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	outer := tempDir(t, c)
	dir := outer + `\managed`
	outside := outer + `\outside`
	run(t, c, `param($A)
[void][IO.Directory]::CreateDirectory($A.d)
[void][IO.Directory]::CreateDirectory($A.o)
[IO.File]::WriteAllText($A.d + '\inside.txt', 'x')
[IO.File]::WriteAllText($A.o + '\secret.txt', 'x')
& cmd.exe /c mklink /J "$($A.d)\out" "$($A.o)" | Out-Null
if ($LASTEXITCODE) { throw 'mklink /J' }
$global:LASTEXITCODE = 0`, map[string]any{"d": dir, "o": outside})
	before, beforeFile := sddl(t, c, outside), sddl(t, c, outside+`\secret.txt`)
	entry := windows.Entry{Principal: "S-1-5-32-545", Rights: []string{"Read"}}
	if err := windows.ApplyACL(ctx, c, windows.ACL{Path: dir, Entries: []windows.Entry{entry}}, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sddl(t, c, dir), "BU") {
		t.Errorf("the rule isn't on the folder: %s", sddl(t, c, dir))
	}
	if sddl(t, c, outside) != before || sddl(t, c, outside+`\secret.txt`) != beforeFile {
		t.Error("rules went through a junction inside the folder")
	}
}

// Promised rules are refused in a folder another account can change. Plain
// content isn't, and a folder locked down with its own rules is fine.
func TestRefusesFoldersOthersCanChange(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	base := tempDir(t, c)
	for name, ace := range map[string]string{
		"modify":  "Modify",
		"delete":  "Delete",
		"subdel":  "DeleteSubdirectoriesAndFiles",
		"dacl":    "ChangePermissions",
		"takeown": "TakeOwnership",
		"full":    "FullControl",
	} {
		dir := base + `\` + name
		run(t, c, `param($A)
[void][IO.Directory]::CreateDirectory($A.d)
$s = Get-Acl -LiteralPath $A.d
$s.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-545'), $A.r, 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
Set-Acl -LiteralPath $A.d -AclObject $s`, map[string]any{"d": dir, "r": ace})
		if err := windows.ApplyFile(ctx, c, dir+`\x`, []byte("s"), windows.SecretEntries, nil); err == nil || !strings.Contains(err.Error(), "rename or replace") {
			t.Errorf("%s: file in it: %v", name, err)
		}
		if err := windows.ApplyFile(ctx, c, dir+`\plain`, []byte("s"), nil, nil); err != nil {
			t.Errorf("%s: plain content: %v", name, err)
		}
		if err := windows.ApplyDirectory(ctx, c, dir+`\sub`, windows.SecretEntries); err == nil {
			t.Errorf("%s: folder with rules below it wasn't refused", name)
		}
		if err := windows.ApplyACL(ctx, c, windows.ACL{Path: dir + `\plain`, Entries: windows.SecretEntries}, false); err == nil {
			t.Errorf("%s: rules below it weren't refused", name)
		}
		noTemp(t, c, dir)
	}
	// Adding new entries isn't enough to refuse, and it's the default under C:\.
	dir := base + `\addonly`
	run(t, c, `param($A)
[void][IO.Directory]::CreateDirectory($A.d)
$s = Get-Acl -LiteralPath $A.d
$s.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-545'), 'CreateFiles,AppendData', 'None', 'None', 'Allow')))
Set-Acl -LiteralPath $A.d -AclObject $s`, map[string]any{"d": dir})
	if err := windows.ApplyFile(ctx, c, dir+`\x`, []byte("s"), windows.SecretEntries, nil); err != nil {
		t.Errorf("add-only folder: %v", err)
	}
	drive := `C:\conn3x-test-` + strconv.FormatInt(time.Now().UnixNano(), 36)
	t.Cleanup(func() {
		_, _ = ps.User(context.Background(), c, `param($A) Remove-Item -LiteralPath $A.d -Recurse -Force`, map[string]any{"d": drive}, time.Minute)
	})
	if err := windows.ApplyDirectory(ctx, c, drive, windows.SecretEntries); err != nil {
		t.Fatalf("a locked folder under the drive root: %v", err)
	}
	if err := windows.ApplyDirectory(ctx, c, drive+`\a\b`, nil); err != nil {
		t.Fatalf("a folder below that: %v", err)
	}
	if err := windows.ApplyFile(ctx, c, drive+`\a\b\x`, []byte("s"), windows.SecretEntries, nil); err != nil {
		t.Errorf("a secret in that: %v", err)
	}
}

// A folder someone else already made isn't taken over by adding rules to it.
func TestRefusesFolderOwnedByAnother(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	base := tempDir(t, c)
	dir := base + `\theirs`
	run(t, c, `param($A)
[void][IO.Directory]::CreateDirectory($A.d)
$s = New-Object Security.AccessControl.DirectorySecurity
$s.SetOwner((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-545'))
[IO.Directory]::SetAccessControl($A.d, $s)`, map[string]any{"d": dir})
	if err := windows.ApplyDirectory(ctx, c, dir, windows.SecretEntries); err == nil || !strings.Contains(err.Error(), "belongs to") {
		t.Errorf("folder: %v", err)
	}
	if err := windows.ApplyFile(ctx, c, dir+`\x`, []byte("s"), windows.SecretEntries, nil); err == nil || !strings.Contains(err.Error(), "belongs to") {
		t.Errorf("secret inside: %v", err)
	}
}

// libraryScript runs lib/safepath.ps1 with a body, to test what it holds.
func libraryScript(t *testing.T, body string) string {
	t.Helper()
	lib, err := os.ReadFile("../../internal/conn3x/modules/windows/lib/safepath.ps1")
	if err != nil {
		t.Fatal(err)
	}
	return "param($A)\n" + string(lib) + "\n" + body
}

// While a write runs, nothing on the way can be renamed or deleted, and the
// rename into place still works.
func TestHeldFoldersCantBeSwapped(t *testing.T) {
	c := connect(t)
	dir := tempDir(t, c)
	script := libraryScript(t, `
$leaf = $A.dir + '\a\b'
[void][IO.Directory]::CreateDirectory($leaf)
Lock-Folders $leaf
$out = @()
foreach ($move in @(@($leaf, ($A.dir + '\a\moved')), @(($A.dir + '\a'), ($A.dir + '\moved')))) {
  try { [IO.Directory]::Move($move[0], $move[1]); $out += 'moved' } catch { $out += 'refused' }
}
try { [IO.Directory]::Delete($leaf); $out += 'deleted' } catch { $out += 'refused' }
[IO.File]::WriteAllText($leaf + '\t', 'x')
if ([Conn3xFs]::MoveFileExW($leaf + '\t', $leaf + '\done', 9)) { $out += 'renamed inside' } else { $out += 'rename failed' }
$out -join ','`)
	got := strings.TrimSpace(run(t, c, script, map[string]any{"dir": dir}).Text)
	if got != "refused,refused,refused,renamed inside" {
		t.Errorf("got %s", got)
	}
}

func TestSecretFileRules(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	dir := tempDir(t, c)
	p := dir + `\secret`
	const secret = "s3ntinel-file-value"
	// A file that's already there with loose rules loses them on write.
	run(t, c, `param($A)
[IO.File]::WriteAllText($A.p, 'old')
$s = Get-Acl -LiteralPath $A.p
$s.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier 'S-1-1-0'), 'FullControl', 'Allow')))
Set-Acl -LiteralPath $A.p -AclObject $s`, map[string]any{"p": p})
	if err := windows.ApplyFile(ctx, c, p, []byte(secret), windows.SecretEntries, []string{secret}); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(fileText(t, c, p)); got != b64(secret) {
		t.Error("content differs")
	}
	s, err := windows.ReadPath(ctx, c, p, windows.Principals(windows.SecretEntries, ""), true)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := windows.Exact(s, windows.SecretEntries); err != nil || !ok {
		t.Errorf("rules: %s: %v, %+v", sddl(t, c, p), err, s)
	}
	if strings.Contains(fmt.Sprintf("%+v", s), secret) {
		t.Error("the read holds the content")
	}
	// Failing partway leaves the old file and no temp file, and a thrown
	// message that quotes the secret comes back blanked.
	dirAsFile := dir + `\folder`
	run(t, c, `param($A) [void][IO.Directory]::CreateDirectory($A.p)`, map[string]any{"p": dirAsFile})
	if err := windows.ApplyFile(ctx, c, dirAsFile, []byte(secret), windows.SecretEntries, []string{secret}); err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("err = %v", err)
	}
	noTemp(t, c, dir)
}

// A plain rewrite keeps whatever rules the file already has, unless someone
// else made the file.
func TestPlainRewriteKeepsRules(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	dir := tempDir(t, c)
	p := dir + `\x`
	if err := windows.ApplyFile(ctx, c, p, []byte("one"), nil, nil); err != nil {
		t.Fatal(err)
	}
	entry := windows.Entry{Principal: "S-1-5-32-545", Rights: []string{"Modify"}}
	if err := windows.ApplyACL(ctx, c, windows.ACL{Path: p, Entries: []windows.Entry{entry}}, false); err != nil {
		t.Fatal(err)
	}
	before := sddl(t, c, p)
	if err := windows.ApplyFile(ctx, c, p, []byte("two"), nil, nil); err != nil {
		t.Fatal(err)
	}
	if got := sddl(t, c, p); got != before {
		t.Errorf("rules changed from %s to %s", before, got)
	}
	// Planted by another account, with rules letting it back in.
	run(t, c, `param($A)
$s = Get-Acl -LiteralPath $A.p
$s.SetOwner((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-545'))
Set-Acl -LiteralPath $A.p -AclObject $s`, map[string]any{"p": p})
	if err := windows.ApplyFile(ctx, c, p, []byte("three"), nil, nil); err != nil {
		t.Fatal(err)
	}
	s, err := windows.ReadPath(ctx, c, p, []string{"S-1-5-32-545"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Matches([]windows.Entry{entry}, false, nil, ""); ok {
		t.Error("a planted file's rules survived the write")
	}
	if s.Owner == "S-1-5-32-545" {
		t.Error("the planted owner survived the write")
	}
}

func TestAclModes(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	base := tempDir(t, c)
	dir := base + `\d`
	f := false
	admins := windows.Entry{Principal: "S-1-5-32-544", Rights: []string{"FullControl"}}
	users := windows.Entry{Principal: "S-1-5-32-545", Rights: []string{"ReadAndExecute"}}
	if err := windows.ApplyDirectory(ctx, c, dir, nil); err != nil {
		t.Fatal(err)
	}
	check := func(a windows.ACL, want bool) {
		t.Helper()
		s, err := windows.ReadPath(ctx, c, dir, windows.Principals(a.Entries, a.Owner), false)
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := s.Matches(a.Entries, a.Authoritative, a.Inherit, a.Owner); err != nil || ok != want {
			t.Errorf("%+v: match = %v, %v; sddl %s", a, ok, err, sddl(t, c, dir))
		}
	}
	add := windows.ACL{Path: dir, Entries: []windows.Entry{users}}
	if err := windows.ApplyACL(ctx, c, add, true); err != nil {
		t.Fatal(err)
	}
	check(add, true)
	// Friendly names in any case match the same SIDs, once they resolve.
	check(windows.ACL{Path: dir, Entries: []windows.Entry{{Principal: `builtin\USERS`, Rights: []string{"ReadAndExecute"}}}}, true)
	// Authoritative with inheritance off leaves exactly the list.
	auth := windows.ACL{Path: dir, Entries: []windows.Entry{admins, users}, Authoritative: true, Inherit: &f}
	check(auth, false)
	if err := windows.ApplyACL(ctx, c, auth, true); err != nil {
		t.Fatal(err)
	}
	check(auth, true)
	// Drift: another rule makes it out of sync again.
	run(t, c, `param($A)
$s = Get-Acl -LiteralPath $A.p
$s.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier 'S-1-1-0'), 'Read', 'Allow')))
Set-Acl -LiteralPath $A.p -AclObject $s`, map[string]any{"p": dir})
	check(auth, false)
	if err := windows.ApplyACL(ctx, c, auth, true); err != nil {
		t.Fatal(err)
	}
	check(auth, true)
	// Owner, and a principal that isn't there.
	own := windows.ACL{Path: dir, Owner: "S-1-5-32-544"}
	if err := windows.ApplyACL(ctx, c, own, true); err != nil {
		t.Fatal(err)
	}
	check(own, true)
	if err := windows.ApplyACL(ctx, c, windows.ACL{Path: dir, Entries: []windows.Entry{{Principal: "no-such-account-x", Rights: []string{"Read"}}}}, true); err == nil {
		t.Error("an unknown principal gave no error")
	}
	// Hostile principal stays data.
	if s, err := windows.ReadPath(ctx, c, dir, []string{`'; New-Item C:\marker; '`}, false); err != nil || s.SIDs[`'; New-Item C:\marker; '`] != "" {
		t.Errorf("%+v, %v", s, err)
	}
}

func TestPathReadsChangeNothing(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	dir := tempDir(t, c)
	p := dir + `\x`
	if err := windows.ApplyFile(ctx, c, p, []byte("x"), nil, nil); err != nil {
		t.Fatal(err)
	}
	before, beforeRules := snapshot(t, c, dir), sddl(t, c, p)
	for range 3 {
		if _, err := windows.ReadPath(ctx, c, p, []string{"S-1-5-32-544", `BUILTIN\Users`}, true); err != nil {
			t.Fatal(err)
		}
		if _, err := windows.ReadPath(ctx, c, dir+`\missing`, nil, true); err != nil {
			t.Fatal(err)
		}
	}
	compare(t, before, snapshot(t, c, dir))
	if sddl(t, c, p) != beforeRules {
		t.Error("a read changed rules")
	}
}

// With PowerShell's module and script block logging both on, as a domain policy
// might set them, a secret still reaches no event log, in any encoding we send.
func TestSecretNotInEventLogs(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	dir := tempDir(t, c)
	const secret = "s3ntinel-eventlog-value"
	set := `$b = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
New-Item -Force -Path "$b\ModuleLogging\ModuleNames" | Out-Null
New-Item -Force -Path "$b\ScriptBlockLogging" | Out-Null
Set-ItemProperty -LiteralPath "$b\ModuleLogging" -Name EnableModuleLogging -Value 1
Set-ItemProperty -LiteralPath "$b\ModuleLogging\ModuleNames" -Name '*' -Value '*'
Set-ItemProperty -LiteralPath "$b\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1`
	run(t, c, set, nil)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = ps.User(ctx, c, `Remove-Item -Recurse -Force -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'`, nil, time.Minute)
	})
	since := strings.TrimSpace(run(t, c, `(Get-Date).ToUniversalTime().ToString('o')`, nil).Text)
	if err := windows.ApplyFile(ctx, c, dir+`\secret`, []byte(secret), windows.SecretEntries, []string{secret}); err != nil {
		t.Fatal(err)
	}
	if _, err := windows.ReadPath(ctx, c, dir+`\secret`, []string{"S-1-5-18"}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := windows.RunScript(ctx, c, `param($A) [void]$A.pw`, map[string]any{"pw": secret}, []string{secret}, time.Minute); err != nil {
		t.Fatal(err)
	}
	res := run(t, c, `param($A)
$from = [datetime]$A.since
$n = 0; $hits = @()
foreach ($log in 'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell') {
  foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $from } -ErrorAction SilentlyContinue)) {
    $n++
    foreach ($w in $A.needles) { if ($e.Message -like "*$w*") { $hits += "$log event $($e.Id)" } }
  }
}
"events=$n hits=$($hits -join ',')"`, map[string]any{"since": since, "needles": []string{secret, b64(secret)}})
	got := strings.TrimSpace(res.Text)
	t.Log(got)
	if strings.HasPrefix(got, "events=0") {
		t.Error("logging didn't record anything, so this proves nothing")
	}
	if !strings.HasSuffix(got, "hits=") {
		t.Errorf("a secret is in the event log: %s", got)
	}
}

func regCleanup(t *testing.T, c *ssh.Client, sub string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = ps.User(ctx, c, `param($A) [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree($A.k, $false)`, map[string]any{"k": sub}, time.Minute)
	})
}

func TestRegistryValues(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	sub := `SOFTWARE\Conn3xTest\` + strconv.FormatInt(time.Now().UnixNano(), 36)
	regCleanup(t, c, `SOFTWARE\Conn3xTest`)
	key := `HKLM\` + sub
	for name, v := range map[string]windows.RegistryValue{
		"string":       {Name: "s", Type: "string", Data: "plain"},
		"empty":        {Name: "e", Type: "string", Data: ""},
		"expand":       {Name: "x", Type: "expand_string", Data: `%WINDIR%\app`},
		"default":      {Name: "", Type: "string", Data: "the default value"},
		"dword":        {Name: "d", Type: "dword", Data: "1"},
		"dword top":    {Name: "dt", Type: "dword", Data: "4294967295"},
		"qword top":    {Name: "qt", Type: "qword", Data: "18446744073709551615"},
		"binary":       {Name: "b", Type: "binary", Data: "00ff10"},
		"multi":        {Name: "m", Type: "multi_string", Data: "a\nb c\n$(x)"},
		"single multi": {Name: "m1", Type: "multi_string", Data: "only"},
		"hostile name": {Name: `'; New-Item C:\marker; '`, Type: "string", Data: `$(New-Item C:\marker)`},
		"hostile data": {Name: "h", Type: "string", Data: "a\r\n'\"`$env:WINDIR %PATH% \U0001F680"},
		"wildcard key": {Name: "w*[x]", Type: "string", Data: "x"},
	} {
		v.Key = key
		if err := v.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if a, err := windows.ReadRegistry(ctx, c, v, false); err != nil || a.Exists {
			t.Fatalf("%s before: %+v, %v", name, a, err)
		}
		if err := windows.ApplyRegistry(ctx, c, v); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		a, err := windows.ReadRegistry(ctx, c, v, false)
		if err != nil {
			t.Fatalf("%s read: %v", name, err)
		}
		if ok, err := v.Matches(a); err != nil || !ok {
			t.Errorf("%s: read back %+v, %v", name, a, err)
		}
		// The hash the host gives for a secret is the hash Go works out.
		canon, _ := v.Canonical()
		sum := sha256.Sum256([]byte(canon))
		h, err := windows.ReadRegistry(ctx, c, v, true)
		if err != nil || h.SHA256 != hex.EncodeToString(sum[:]) || h.Data != "" || h.Type != v.Type {
			t.Errorf("%s hash only: %+v, %v", name, h, err)
		}
	}
	// A value left unexpanded stays in sync, whatever the variable holds.
	x := windows.RegistryValue{Key: key, Name: "x", Type: "expand_string", Data: `%WINDIR%\app`}
	if a, _ := windows.ReadRegistry(ctx, c, x, false); a.Data != x.Data {
		t.Errorf("expanded: %+v", a)
	}
	// A different type or value is drift.
	d := windows.RegistryValue{Key: key, Name: "d", Type: "string", Data: "1"}
	a, err := windows.ReadRegistry(ctx, c, d, false)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := d.Matches(a); ok {
		t.Error("a dword matched a string")
	}
	if err := windows.ApplyRegistryRemove(ctx, c, d); err != nil {
		t.Fatal(err)
	}
	if a, _ := windows.ReadRegistry(ctx, c, d, false); a.Exists {
		t.Error("remove left the value")
	}
	if err := windows.ApplyRegistryRemove(ctx, c, d); err != nil {
		t.Errorf("removing it twice: %v", err)
	}
	if got := strings.TrimSpace(run(t, c, `Test-Path -LiteralPath 'C:\marker'`, nil).Text); got != "False" {
		t.Error("a hostile value ran")
	}
}

func TestServiceStates(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	// A service nothing else needs here, outside any load order group, which
	// Windows wouldn't allow to start late.
	const name = "W32Time"
	restore := run(t, c, `param($A) $s = Get-Service -Name $A.n; "$($s.StartType) $($s.Status)"`, map[string]any{"n": name}).Text
	t.Logf("before: %s", restore)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_ = windows.ApplyService(ctx, c, windows.Service{Name: name, StartMode: "auto", State: "running"})
	})
	for _, s := range []windows.Service{
		{Name: name, StartMode: "manual", State: "stopped"},
		{Name: name, StartMode: "delayed", State: "running"},
		{Name: name, StartMode: "auto"},
		{Name: name, State: "stopped"},
		{Name: name, StartMode: "disabled"},
		{Name: name, StartMode: "auto", State: "running"},
	} {
		if err := s.Validate(); err != nil {
			t.Fatal(err)
		}
		if err := windows.ApplyService(ctx, c, s); err != nil {
			t.Fatalf("%+v: %v", s, err)
		}
		exists, ok, err := windows.ServiceInSync(ctx, c, s)
		if err != nil || !exists || !ok {
			t.Errorf("%+v: exists %v, in sync %v, %v", s, exists, ok, err)
		}
	}
	// What was just set doesn't match something else.
	if _, ok, _ := windows.ServiceInSync(ctx, c, windows.Service{Name: name, State: "stopped"}); ok {
		t.Error("a running service matched stopped")
	}
	if exists, _, err := windows.ServiceInSync(ctx, c, windows.Service{Name: "no-such-service", State: "running"}); err != nil || exists {
		t.Errorf("missing service: %v, %v", exists, err)
	}
	for _, bad := range []string{`*`, `W32T?me`, `a';b`, `$(x)'`, `[a]`, "a\nb"} {
		if (windows.Service{Name: bad, State: "running"}).Validate() == nil {
			t.Errorf("accepted service name %q", bad)
		}
	}
}

func TestFeature(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	f := windows.Feature{Name: "Telnet-Client"}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		_, _ = windows.ApplyFeature(ctx, c, windows.Feature{Name: f.Name, Absent: true}, 10*time.Minute)
	})
	before := snapshot(t, c, "")
	if ok, pending, err := windows.FeatureInSync(ctx, c, f); err != nil || ok || pending {
		t.Fatalf("before: %v, %v, %v", ok, pending, err)
	}
	compare(t, before, snapshot(t, c, ""))
	restart, err := windows.ApplyFeature(ctx, c, f, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("restart needed: %v", restart)
	if ok, _, err := windows.FeatureInSync(ctx, c, f); err != nil || !ok {
		t.Errorf("after: %v, %v", ok, err)
	}
	if _, _, err := windows.FeatureInSync(ctx, c, windows.Feature{Name: "No-Such-Feature"}); err == nil {
		t.Error("a missing feature gave no error")
	}
	for _, bad := range []string{`*`, `Web-*`, `a';b`, `$(x)`, "a b", "-x"} {
		if (windows.Feature{Name: bad}).Validate() == nil {
			t.Errorf("accepted feature name %q", bad)
		}
	}
}

func TestSystemReadsChangeNothing(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	before := snapshot(t, c, "")
	for range 3 {
		if _, _, err := windows.FeatureInSync(ctx, c, windows.Feature{Name: "Web-Server"}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := windows.ServiceInSync(ctx, c, windows.Service{Name: "W32Time", State: "running"}); err != nil {
			t.Fatal(err)
		}
		v := windows.RegistryValue{Key: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, Name: "CurrentBuild", Type: "string"}
		if _, err := windows.ReadRegistry(ctx, c, v, false); err != nil {
			t.Fatal(err)
		}
		if _, err := windows.ReadUser(ctx, c, "Guest"); err != nil {
			t.Fatal(err)
		}
		if _, err := windows.ReadGroup(ctx, c, windows.Group{Name: "Administrators", Members: []string{"Guest", "c3-nobody"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := windows.PackageInstalled(ctx, c, sevenZipCode); err != nil {
			t.Fatal(err)
		}
		if _, err := windows.ReadTask(ctx, c, windows.Task{Path: `\Microsoft\Windows\Defrag\`, Name: "ScheduledDefrag", User: "SYSTEM"}); err != nil {
			t.Fatal(err)
		}
		// Not a DC, with or without AD DS: the forest reads as missing.
		if a, err := windows.ReadForest(ctx, c); err != nil || a.Forest != "" {
			t.Fatalf("forest: %+v, %v", a, err)
		}
		if _, err := windows.ReadDNSClient(ctx, c, windows.DNSClient{}); err != nil {
			t.Fatal(err)
		}
		// Off a DC these read as nothing there; on one, as whatever is.
		if _, err := windows.ReadOU(ctx, c, windows.OU{Name: "c3-none"}); err != nil {
			t.Fatal(err)
		}
		if _, err := windows.ReadADGroup(ctx, c, windows.ADGroup{Name: "Domain Admins", Members: []string{"c3-nobody"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := windows.ReadADUser(ctx, c, windows.ADUser{Name: "c3-nobody", Path: "OU=None,DC=c3,DC=test"}); err != nil {
			t.Fatal(err)
		}
		// A key that doesn't exist must stay that way.
		if _, err := windows.ReadRegistry(ctx, c, windows.RegistryValue{Key: `HKLM\SOFTWARE\Conn3xNeverMade`, Name: "x", Type: "string"}, false); err != nil {
			t.Fatal(err)
		}
	}
	compare(t, before, snapshot(t, c, ""))
	if got := strings.TrimSpace(run(t, c, `Test-Path -LiteralPath 'HKLM:\SOFTWARE\Conn3xNeverMade'`, nil).Text); got != "False" {
		t.Error("a read made a key")
	}
}
