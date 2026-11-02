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
		f.Hostname == "" || !strings.HasPrefix(f.PowerShell, "5.1") || f.Edition == "" || f.InstallationType == "" {
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
  }%[8]s
}
`, extraData, host, user, key, hostKey, marker, secretFile, reboot)
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
}
