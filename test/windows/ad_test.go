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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// keepDNS puts an interface's IPv4 DNS servers back as they were when the test
// ends: from DHCP again if they came from there.
func keepDNS(t *testing.T, c *ssh.Client, index int) {
	t.Helper()
	static := strings.TrimSpace(run(t, c, `param($A)
$g = (Get-NetAdapter -InterfaceIndex $A.i).InterfaceGuid
[string](Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\' + $g)).NameServer`, map[string]any{"i": index}).Text)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = ps.User(ctx, c, `param($A)
if ($A.static) { Set-DnsClientServerAddress -InterfaceIndex $A.i -ServerAddresses ($A.static -split ',') }
else { Set-DnsClientServerAddress -InterfaceIndex $A.i -ResetServerAddresses }`, map[string]any{"i": index, "static": static}, time.Minute)
	})
}

func TestDNSClient(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	before, err := windows.ReadDNSClient(ctx, c, windows.DNSClient{})
	if err != nil || !before.Found || len(before.IPv4) == 0 {
		t.Fatalf("the default interface: %+v, %v", before, err)
	}
	t.Logf("%s (%d): IPv4 %v, IPv6 %v", before.Alias, before.Index, before.IPv4, before.IPv6)
	keepDNS(t, c, before.Index)
	if len(before.IPv6) == 0 {
		// Something to leave alone, so the check below means something.
		run(t, c, `param($A) Set-DnsClientServerAddress -InterfaceIndex $A.i -ServerAddresses '2001:db8::53'`, map[string]any{"i": before.Index})
		if before, err = windows.ReadDNSClient(ctx, c, windows.DNSClient{}); err != nil || len(before.IPv6) != 1 {
			t.Fatalf("with an IPv6 server: %+v, %v", before, err)
		}
	}

	// The servers it has, plus one that answers nothing, second, so lookups
	// keep working while the test runs.
	want := windows.DNSClient{Servers: append(slices.Clone(before.IPv4), "192.0.2.53")}
	if want.Matches(before) {
		t.Fatal("matched before the change")
	}
	if err := windows.ApplyDNSClient(ctx, c, want); err != nil {
		t.Fatal(err)
	}
	after, err := windows.ReadDNSClient(ctx, c, want)
	if err != nil || !want.Matches(after) {
		t.Fatalf("after: %+v, %v", after, err)
	}
	if !slices.Equal(before.IPv6, after.IPv6) {
		t.Errorf("IPv6 servers changed from %v to %v, with only IPv4 asked for", before.IPv6, after.IPv6)
	}
	// By name, the same interface.
	named := windows.DNSClient{Interface: after.Alias, Servers: want.Servers}
	if a, err := windows.ReadDNSClient(ctx, c, named); err != nil || a.Index != before.Index || !named.Matches(a) {
		t.Errorf("by name: %+v, %v", a, err)
	}
	missing := windows.DNSClient{Interface: "Conn3x No Such Interface", Servers: want.Servers}
	if a, err := windows.ReadDNSClient(ctx, c, missing); err != nil || a.Found {
		t.Errorf("missing interface: %+v, %v", a, err)
	}
	if err := windows.ApplyDNSClient(ctx, c, missing); err == nil || !strings.Contains(err.Error(), "no network interface named") {
		t.Errorf("apply to a missing interface: %v", err)
	}
}

// The folders AD would keep its database and SYSVOL in must be admin-only, owned
// by an admin and no link, so nobody else could read ntds.dit or plant a logon
// script. The top of a new volume, like C:\ here, lets any user make a folder
// and own it. CONN3X_WIN_AD_ROOT names another, such as F:\. Apply checks the
// folders before it needs AD DS, so this runs anywhere.
func TestADForestRefusesOpenFolders(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	root := os.Getenv("CONN3X_WIN_AD_ROOT")
	if root == "" {
		root = `C:\`
	}
	user := accountName(t, c, "c3f")
	run(t, c, `param($A) New-LocalUser -Name $A.u -Password ([Net.NetworkCredential]::new('', $A.p).SecurePassword) | Out-Null`, map[string]any{"u": user, "p": "Aa1!" + randHex(12)})
	base := root + "c3f-" + randHex(4)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = ps.User(ctx, c, `param($A) Get-Item -LiteralPath ($A.b + '-link') -ErrorAction SilentlyContinue | ForEach-Object { $_.Delete() }
foreach ($d in 'owned', 'open', 'admin', 'addfile', 'inherit', 'full') { if ([IO.Directory]::Exists($A.b + '-' + $d)) { [IO.Directory]::Delete($A.b + '-' + $d, $true) } }`, map[string]any{"b": base}, time.Minute)
	})
	run(t, c, `param($A)
$owned = $A.b + '-owned'; $open = $A.b + '-open'; $admin = $A.b + '-admin'
[void][IO.Directory]::CreateDirectory($owned)
# As if the user had made it: icacls enables the restore right to hand it over.
& icacls.exe $owned /setowner $A.u | Out-Null
if ($LASTEXITCODE) { throw 'setowner' }
& cmd.exe /c mklink /J ($A.b + '-link') $env:PUBLIC | Out-Null
if ($LASTEXITCODE) { throw 'mklink' }
[void][IO.Directory]::CreateDirectory($open)
& icacls.exe $open /grant '*S-1-5-32-545:(OI)(CI)M' | Out-Null
# Admin-only, plus one more rule for Users when asked.
function New-AdminFolder($p, $rights, $propagation = 'None') {
  $sec = New-Object Security.AccessControl.DirectorySecurity
  $sec.SetAccessRuleProtection($true, $false)
  foreach ($s in 'S-1-5-18', 'S-1-5-32-544') {
    $sec.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule([Security.Principal.SecurityIdentifier]$s, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
  }
  if ($rights) { $sec.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule([Security.Principal.SecurityIdentifier]'S-1-5-32-545', $rights, 'ContainerInherit,ObjectInherit', $propagation, 'Allow'))) }
  [void][IO.Directory]::CreateDirectory($p, $sec)
}
New-AdminFolder $admin
# Users may add files and folders here, but not delete or rename: only the
# admin-only check sees that, not the folder chain's.
New-AdminFolder ($A.b + '-addfile') 'CreateFiles, AppendData'
# Users get Modify on what's inside only.
New-AdminFolder ($A.b + '-inherit') 'Modify' 'InheritOnly'
# Admin-only, but with something already in it.
New-AdminFolder ($A.b + '-full')
[IO.File]::WriteAllText($A.b + '-full\ntds.dit', 'not empty')`, map[string]any{"b": base, "u": user})
	for attr, want := range map[string]string{
		"owned": "belongs to", "link": "link or junction", "open": "can rename or replace",
		"addfile": "can add or replace files", "inherit": "can add or replace files", "full": "isn't empty",
	} {
		for _, f := range []windows.Forest{
			{DomainName: "lab.conn3x.test", DatabasePath: base + "-" + attr},
			{DomainName: "lab.conn3x.test", DatabasePath: base + "-admin", SysvolPath: base + "-" + attr},
		} {
			_, err := windows.ApplyForest(ctx, c, f, "Xx9!unused", 5*time.Minute)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s: %v", attr, err)
			}
		}
	}
	// An admin-only folder passes the check and gets as far as AD DS, or
	// further on a host that has it, which this test mustn't promote.
	if a, _ := windows.ReadForest(ctx, c); a.Forest == "" {
		has := strings.TrimSpace(run(t, c, `[bool](Get-Module -ListAvailable -Name ADDSDeployment)`, nil).Text)
		if has == "False" {
			_, err := windows.ApplyForest(ctx, c, windows.Forest{DomainName: "lab.conn3x.test", DatabasePath: base + "-admin"}, "Xx9!unused", 5*time.Minute)
			if err == nil || !strings.Contains(err.Error(), "AD DS is not installed") {
				t.Errorf("admin-only folder: %v", err)
			}
		}
	}
}

// TestADForestFlow makes a forest through the binary, as the module page
// shows: feature, forest, reboot, AD ready, then DNS on the DC itself. It
// reboots the host and leaves it a domain controller, so it runs only on a VM
// that's thrown away afterwards, with CONN3X_WIN_AD=1.
func TestADForestFlow(t *testing.T) {
	bin := os.Getenv("CONN3X_WIN_BIN")
	if bin == "" || os.Getenv("CONN3X_WIN_AD") == "" {
		t.Skip("needs CONN3X_WIN_BIN and CONN3X_WIN_AD=1, on a VM to throw away")
	}
	c := connect(t)
	ctx := context.Background()
	facts, err := windows.Gather(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if a, err := windows.ReadForest(ctx, c); err != nil || a.Forest != "" || a.Member != "" {
		t.Fatalf("not a workgroup server: %+v, %v", a, err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	sentinel := "s3ntinel-Dsrm-" + hex.EncodeToString(b) + "Q"
	needles := []string{sentinel, b64(sentinel)}

	// Module logging and command lines on, as in TestUserPasswordSentinel.
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
	since := strings.TrimSpace(run(t, c, `(Get-Date).ToUniversalTime().ToString('o')`, nil).Text)

	dir := t.TempDir()
	key := env(t, "CONN3X_WIN_KEY")
	if abs, err := filepath.Abs(key); err == nil {
		key = abs
	}
	rest := `  step "promoted" {
    windows_reboot {
      only_if_pending = true
      timeout         = "15m"
    }
  }
  step "adws" {
    windows_wait_for {
      port    = 9389
      timeout = "10m"
    }
  }
  step "ad_answers" {
    windows_powershell {
      script = <<-PS
        $deadline = (Get-Date).AddMinutes(5)
        while ($true) {
          try { Import-Module ActiveDirectory; Get-ADDomain | Out-Null; break }
          catch { if ((Get-Date) -gt $deadline) { throw } ; Start-Sleep -Seconds 5 }
        }
      PS
      unless = "Import-Module ActiveDirectory; Get-ADDomain | Out-Null"
    }
  }
  # Its own address first, then loopback, as for any DC.
  step "dns" {
    windows_dns_client {
      servers = [%[1]q, "127.0.0.1"]
    }
  }
`
	rest = fmt.Sprintf(rest, facts.IPv4)
	config := func(steps string) string {
		return fmt.Sprintf(`
variable "dsrm" {
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
    timeout          = "15m"
  }
  step "ad_ds" {
    windows_feature {
      name                     = "AD-Domain-Services"
      include_management_tools = true
    }
  }
  step "forest" {
    windows_ad_forest {
      domain_name           = "lab.conn3x.test"
      netbios_name          = "LAB"
      safe_mode_password_wo = var.dsrm
    }
  }
  %[5]s
}
`, env(t, "CONN3X_WIN_HOST"), env(t, "CONN3X_WIN_USER"), key, env(t, "CONN3X_WIN_HOST_KEY"), steps)
	}
	write := func(steps string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(config(steps)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	logFile := filepath.Join(dir, "trace.log")
	tool := func(args ...string) (string, int) {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Dir = dir
		// Through the environment: a -var would put it in Tofu's own log line.
		cmd.Env = append(os.Environ(), "TF_VAR_dsrm="+sentinel, "TF_LOG=trace", "TF_LOG_PATH="+logFile)
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return string(out), ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return string(out), 0
	}
	if out, code := tool("init", "-no-color"); code != 0 {
		t.Fatal(out)
	}
	var seen strings.Builder
	apply := func(planArgs ...string) {
		t.Helper()
		out, code := tool(append([]string{"plan", "-no-color", "-input=false", "-detailed-exitcode", "-out=tfplan"}, planArgs...)...)
		seen.WriteString(out)
		if code != 2 {
			t.Fatalf("plan: exit %d\n%s", code, out)
		}
		start := time.Now()
		out, code = tool("apply", "-no-color", "-input=false", "tfplan")
		seen.WriteString(out)
		if code != 0 {
			t.Fatalf("apply: exit %d\n%s", code, out)
		}
		t.Logf("apply took %s", time.Since(start).Round(time.Second))
	}

	// First as a run that stops before its reboot: promoted, and Windows
	// reports the reboot pending, so windows_reboot with only_if_pending
	// would plan it.
	write("")
	apply()
	if a, err := windows.ReadForest(ctx, c); err != nil || a.Forest != "lab.conn3x.test" || !a.Pending {
		t.Fatalf("before the reboot: %+v, %v", a, err)
	}
	if p, err := windows.PendingReboot(ctx, c); err != nil || !p {
		t.Fatalf("no reboot pending after promotion: %v", err)
	}
	if got := strings.TrimSpace(run(t, c, `Test-Path -LiteralPath 'HKLM:\SOFTWARE\Conn3x\RebootRequired'`, nil).Text); got != "True" {
		t.Error("promotion left no reboot marker")
	}
	// In this state Get-WindowsFeature takes about 100 seconds, close to the
	// read deadline, so the feature isn't refreshed for this plan.
	write(rest)
	apply("-refresh=false")

	// Snapshot after the apply, then plan twice: empty, and nothing changed.
	c = connect(t)
	snap := snapshot(t, c, "")
	for range 2 {
		out, code := tool("plan", "-no-color", "-input=false", "-detailed-exitcode")
		seen.WriteString(out)
		if code != 0 {
			t.Fatalf("second plan: exit %d\n%s", code, out)
		}
	}
	compare(t, snap, snapshot(t, c, ""))
	a, err := windows.ReadForest(ctx, c)
	if err != nil || a.Forest != "lab.conn3x.test" || a.Pending {
		t.Errorf("after: %+v, %v", a, err)
	}
	if who := strings.TrimSpace(run(t, c, `whoami`, nil).Text); !strings.HasPrefix(strings.ToLower(who), `lab\`) {
		t.Errorf("logged in as %q after promotion", who)
	}

	state, code := tool("state", "pull")
	if code != 0 {
		t.Fatal(state)
	}
	trace, _ := os.ReadFile(logFile)
	saved, _ := os.ReadFile(filepath.Join(dir, "tfplan"))
	for name, text := range map[string]string{"plan and apply output": seen.String(), "state": state, "trace log": string(trace), "saved plan": string(saved)} {
		for _, w := range needles {
			if strings.Contains(text, w) {
				t.Errorf("the password is in the %s", name)
			}
		}
	}
	if len(trace) == 0 || len(saved) == 0 || !strings.Contains(state, "lab.conn3x.test") {
		t.Error("no trace log or no state, so this proves nothing")
	}

	res := run(t, c, `param($A)
$from = [datetime]$A.since
$n = @{}; $hits = @()
foreach ($q in @(@{ LogName = 'Microsoft-Windows-PowerShell/Operational' }, @{ LogName = 'Windows PowerShell' }, @{ LogName = 'Security'; Id = 4688 }, @{ LogName = 'Directory Service' })) {
  $q.StartTime = $from
  foreach ($e in @(Get-WinEvent -FilterHashtable $q -ErrorAction SilentlyContinue)) {
    $n[$q.LogName] = 1 + [int]$n[$q.LogName]
    foreach ($w in $A.needles) { if ($e.Message -and $e.Message.Contains($w)) { $hits += "$($q.LogName) event $($e.Id)" } }
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
		t.Errorf("the password is in the event log: %s", got)
	}
	run(t, c, `Remove-Item -Recurse -Force -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'`, nil)
	res = run(t, c, `param($A)
$hits = @(); $files = 0
foreach ($d in @('C:\Windows\debug', 'C:\ProgramData\ssh\logs', 'C:\Windows\Temp', $env:TEMP, 'C:\Windows\System32\LogFiles')) {
  foreach ($f in @(Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue)) {
    try { $text = [IO.File]::ReadAllText($f.FullName) } catch { continue }
    $files++
    foreach ($w in $A.needles) { if ($text.Contains($w)) { $hits += $f.FullName } }
  }
}
$dcpromo = Test-Path -LiteralPath 'C:\Windows\debug\dcpromo.log'
"files=$files dcpromo=$dcpromo hits=$($hits -join ',')"`, map[string]any{"needles": needles})
	got = strings.TrimSpace(res.Text)
	t.Log(got)
	if !strings.HasSuffix(got, "hits=") || !strings.Contains(got, "dcpromo=True") {
		t.Errorf("files: %s", got)
	}
}
