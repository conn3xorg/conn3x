// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build windowshost

package windowshost

import (
	"context"
	"crypto/rand"
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

// 7-Zip 24.09's MSI, for the download path.
const (
	sevenZipURL  = "https://github.com/ip7z/7zip/releases/download/24.09/7z2409-x64.msi"
	sevenZipSum  = "ec6af1ea0367d16dde6639a89a080a524cebc4d4bedfe00ed0cac4b865a918d8"
	sevenZipCode = "{23170F69-40C1-2702-2409-000001000000}"
)

func newGUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return strings.ToUpper(fmt.Sprintf("{%x-%x-%x-%x-%x}", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]))
}

// testMSI is a package built on the host, with no files: it writes the ECHO
// property to HKLM\SOFTWARE\Conn3xTestPkg\<code>, and with reboot, asks for a
// restart, so msiexec exits 3010.
type testMSI struct {
	Path, SHA256, Code string
}

func buildMSI(t *testing.T, c *ssh.Client, dir string, reboot bool) testMSI {
	t.Helper()
	code := newGUID()
	key := `SOFTWARE\Conn3xTestPkg\` + code
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	sql := []string{
		"CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` LONGCHAR NOT NULL LOCALIZABLE PRIMARY KEY `Property`)",
		"CREATE TABLE `Directory` (`Directory` CHAR(72) NOT NULL, `Directory_Parent` CHAR(72), `DefaultDir` CHAR(255) NOT NULL LOCALIZABLE PRIMARY KEY `Directory`)",
		"CREATE TABLE `Component` (`Component` CHAR(72) NOT NULL, `ComponentId` CHAR(38), `Directory_` CHAR(72) NOT NULL, `Attributes` SHORT NOT NULL, `Condition` CHAR(255), `KeyPath` CHAR(72) PRIMARY KEY `Component`)",
		"CREATE TABLE `Feature` (`Feature` CHAR(38) NOT NULL, `Feature_Parent` CHAR(38), `Title` CHAR(64) LOCALIZABLE, `Description` CHAR(255) LOCALIZABLE, `Display` SHORT, `Level` SHORT NOT NULL, `Directory_` CHAR(72), `Attributes` SHORT NOT NULL PRIMARY KEY `Feature`)",
		"CREATE TABLE `FeatureComponents` (`Feature_` CHAR(38) NOT NULL, `Component_` CHAR(72) NOT NULL PRIMARY KEY `Feature_`, `Component_`)",
		"CREATE TABLE `Registry` (`Registry` CHAR(72) NOT NULL, `Root` SHORT NOT NULL, `Key` CHAR(255) NOT NULL LOCALIZABLE, `Name` CHAR(255) LOCALIZABLE, `Value` LONGCHAR LOCALIZABLE, `Component_` CHAR(72) NOT NULL PRIMARY KEY `Registry`)",
		"CREATE TABLE `File` (`File` CHAR(72) NOT NULL, `Component_` CHAR(72) NOT NULL, `FileName` CHAR(255) NOT NULL LOCALIZABLE, `FileSize` LONG NOT NULL, `Version` CHAR(72), `Language` CHAR(20), `Attributes` SHORT, `Sequence` SHORT NOT NULL PRIMARY KEY `File`)",
		"CREATE TABLE `Media` (`DiskId` SHORT NOT NULL, `LastSequence` SHORT NOT NULL, `DiskPrompt` CHAR(64) LOCALIZABLE, `Cabinet` CHAR(255), `VolumeLabel` CHAR(32), `Source` CHAR(72) PRIMARY KEY `DiskId`)",
		"CREATE TABLE `InstallExecuteSequence` (`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), `Sequence` SHORT PRIMARY KEY `Action`)",
		"INSERT INTO `Directory` (`Directory`, `DefaultDir`) VALUES ('TARGETDIR', 'SourceDir')",
		"INSERT INTO `Component` (`Component`, `ComponentId`, `Directory_`, `Attributes`, `KeyPath`) VALUES ('Main', " + q(newGUID()) + ", 'TARGETDIR', 260, 'Reg')",
		"INSERT INTO `Registry` (`Registry`, `Root`, `Key`, `Name`, `Value`, `Component_`) VALUES ('Reg', 2, " + q(key) + ", 'echo', '[ECHO]', 'Main')",
		"INSERT INTO `Feature` (`Feature`, `Title`, `Display`, `Level`, `Attributes`) VALUES ('Main', 'Main', 1, 1, 0)",
		"INSERT INTO `FeatureComponents` (`Feature_`, `Component_`) VALUES ('Main', 'Main')",
		"INSERT INTO `Media` (`DiskId`, `LastSequence`) VALUES (1, 0)",
	}
	for k, v := range map[string]string{
		"ProductCode": code, "ProductName": "Conn3x test package", "ProductVersion": "1.0.0", "Manufacturer": "Conn3x",
		"ProductLanguage": "1033", "UpgradeCode": newGUID(), "ALLUSERS": "1", "ECHO": "none",
	} {
		sql = append(sql, "INSERT INTO `Property` (`Property`, `Value`) VALUES ("+q(k)+", "+q(v)+")")
	}
	seq := map[string]int{
		"CostInitialize": 800, "FileCost": 900, "CostFinalize": 1000, "InstallValidate": 1400, "InstallInitialize": 1500,
		"ProcessComponents": 1600, "UnpublishFeatures": 1800, "RemoveRegistryValues": 2600, "WriteRegistryValues": 5000,
		"RegisterUser": 6000, "RegisterProduct": 6100, "PublishFeatures": 6300, "PublishProduct": 6400, "InstallFinalize": 6600,
	}
	for a, n := range seq {
		sql = append(sql, fmt.Sprintf("INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('%s', %d)", a, n))
	}
	if reboot {
		sql = append(sql, "INSERT INTO `InstallExecuteSequence` (`Action`, `Condition`, `Sequence`) VALUES ('ScheduleReboot', 'NOT REMOVE', 6590)")
	}
	path := dir + `\` + strings.Trim(code, "{}") + ".msi"
	res := run(t, c, `param($A)
function Invoke-Com($o, [string]$name, [string]$kind, $list) { $o.GetType().InvokeMember($name, $kind, $null, $o, $list) }
$i = New-Object -ComObject WindowsInstaller.Installer
$db = Invoke-Com $i 'OpenDatabase' 'InvokeMethod' @($A.path, 3)
foreach ($s in $A.sql) {
  $v = Invoke-Com $db 'OpenView' 'InvokeMethod' @($s)
  [void](Invoke-Com $v 'Execute' 'InvokeMethod' $null)
  [void](Invoke-Com $v 'Close' 'InvokeMethod' $null)
  [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($v)
}
$si = Invoke-Com $db 'SummaryInformation' 'GetProperty' @(20)
foreach ($p in @(@(2, 'Installation Database'), @(3, 'Conn3x test package'), @(7, 'x64;1033'), @(9, $A.package), @(14, 200), @(15, 2))) {
  [void](Invoke-Com $si 'Property' 'SetProperty' @($p[0], $p[1]))
}
[void](Invoke-Com $si 'Persist' 'InvokeMethod' $null)
[void](Invoke-Com $db 'Commit' 'InvokeMethod' $null)
[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($si)
[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($db)
[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($i)
$si = $db = $i = $v = $null
[GC]::Collect(); [GC]::WaitForPendingFinalizers()
(Get-FileHash -LiteralPath $A.path -Algorithm SHA256).Hash.ToLowerInvariant()`, map[string]any{"path": path, "sql": sql, "package": newGUID()})
	m := testMSI{Path: path, SHA256: strings.TrimSpace(res.Text), Code: code}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		_, _ = windows.ApplyPackage(ctx, c, windows.Package{ProductCode: code, Absent: true}, 5*time.Minute)
		_, _ = ps.User(ctx, c, `param($A) [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree($A.k, $false)`, map[string]any{"k": key}, time.Minute)
	})
	return m
}

// echoed is what the test package wrote for its ECHO property.
func echoed(t *testing.T, c *ssh.Client, code string) string {
	t.Helper()
	return run(t, c, `param($A) $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Conn3xTestPkg\' + $A.c); if ($k) { [string]$k.GetValue('echo') }`, map[string]any{"c": code}).Text
}

// clearRebootMarker undoes what a 3010 left, so other tests start clean.
func clearRebootMarker(t *testing.T, c *ssh.Client) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = ps.User(ctx, c, `[Microsoft.Win32.Registry]::LocalMachine.DeleteSubKey('SOFTWARE\Conn3x\RebootRequired', $false)`, nil, time.Minute)
	})
}

func TestPackageFromSource(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	dir := tempDir(t, c)
	m := buildMSI(t, c, dir, false)
	if ok, err := windows.PackageInstalled(ctx, c, m.Code); err != nil || ok {
		t.Fatalf("before: %v, %v", ok, err)
	}
	// A property value with everything msiexec, cmd.exe or PowerShell might
	// read as syntax arrives as one literal value.
	value := `say "hi" $(New-Item C:\marker) %PATH% ; & | B="x" C:\dir\`
	p := windows.Package{ProductCode: strings.ToLower(m.Code), Source: m.Path, SHA256: strings.ToUpper(m.SHA256), Properties: map[string]string{"ECHO": value}}
	restart, err := windows.ApplyPackage(ctx, c, p, 10*time.Minute)
	if err != nil || restart {
		t.Fatalf("install: restart %v, %v", restart, err)
	}
	if ok, _ := windows.PackageInstalled(ctx, c, m.Code); !ok {
		t.Fatal("not listed as installed")
	}
	if got := strings.TrimRight(echoed(t, c, m.Code), "\r\n"); got != value {
		t.Errorf("property arrived as %q", got)
	}
	// Staged copies don't stay, and only SYSTEM and Administrators have rights
	// on the folder.
	res := run(t, c, `$d = Join-Path $env:ProgramData 'Conn3x\packages'
$acl = Get-Acl -LiteralPath $d
"files=$(@(Get-ChildItem -LiteralPath $d -Force).Count) sids=$((@($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)) -join ',')"`, nil)
	if got := strings.TrimSpace(res.Text); got != "files=0 sids=S-1-5-18,S-1-5-32-544" {
		t.Errorf("staging folder: %s", got)
	}
	if _, err := windows.ApplyPackage(ctx, c, windows.Package{ProductCode: m.Code, Absent: true}, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	if ok, _ := windows.PackageInstalled(ctx, c, m.Code); ok {
		t.Error("still installed after removal")
	}
	if got := strings.TrimSpace(run(t, c, `Test-Path -LiteralPath 'C:\marker'`, nil).Text); got != "False" {
		t.Error("a property value ran")
	}
}

// A file that doesn't match its SHA-256 never reaches msiexec, and goes.
func TestPackageWrongHash(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	m := buildMSI(t, c, tempDir(t, c), false)
	// What a run that died would leave in the staging folder goes too.
	run(t, c, `$d = Join-Path $env:ProgramData 'Conn3x\packages'; [void][IO.Directory]::CreateDirectory($d); [IO.File]::WriteAllText((Join-Path $d 'stray.msi'), 'x')`, nil)
	wrong := strings.Repeat("0", 64)
	_, err := windows.ApplyPackage(ctx, c, windows.Package{ProductCode: m.Code, Source: m.Path, SHA256: wrong}, 10*time.Minute)
	if err == nil || !strings.Contains(err.Error(), "nothing was installed") {
		t.Fatalf("err = %v", err)
	}
	if ok, _ := windows.PackageInstalled(ctx, c, m.Code); ok {
		t.Error("installed anyway")
	}
	if got := strings.TrimSpace(run(t, c, `@(Get-ChildItem -LiteralPath (Join-Path $env:ProgramData 'Conn3x\packages') -Force).Count`, nil).Text); got != "0" {
		t.Errorf("%s files left in the staging folder", got)
	}
}

// A staging folder someone else could change is refused, not used.
func TestPackageRefusesOpenStagingFolder(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	m := buildMSI(t, c, tempDir(t, c), false)
	reset := `$d = Join-Path $env:ProgramData 'Conn3x\packages'; if ([IO.Directory]::Exists($d)) { [IO.Directory]::Delete($d, $true) }`
	t.Cleanup(func() { _, _ = ps.User(context.Background(), c, reset, nil, time.Minute) })
	run(t, c, reset+`
[void][IO.Directory]::CreateDirectory($d)
$acl = Get-Acl -LiteralPath $d
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(([Security.Principal.SecurityIdentifier]'S-1-5-32-545'), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
Set-Acl -LiteralPath $d -AclObject $acl`, nil)
	_, err := windows.ApplyPackage(ctx, c, windows.Package{ProductCode: m.Code, Source: m.Path, SHA256: m.SHA256}, 10*time.Minute)
	if err == nil || !strings.Contains(err.Error(), "can rename or replace") {
		t.Fatalf("err = %v", err)
	}
	if ok, _ := windows.PackageInstalled(ctx, c, m.Code); ok {
		t.Error("installed from an open folder")
	}
}

// A package that asks for a restart reports it, and leaves the need where
// windows_reboot looks.
func TestPackageAsksForReboot(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	clearRebootMarker(t, c)
	m := buildMSI(t, c, tempDir(t, c), true)
	restart, err := windows.ApplyPackage(ctx, c, windows.Package{ProductCode: m.Code, Source: m.Path, SHA256: m.SHA256}, 10*time.Minute)
	if err != nil || !restart {
		t.Fatalf("restart %v, %v", restart, err)
	}
	if pending, err := windows.PendingReboot(ctx, c); err != nil || !pending {
		t.Errorf("pending = %v, %v", pending, err)
	}
	// Only the marker is volatile: an ordinary key still fits beside it.
	res := run(t, c, `try { $k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SOFTWARE\Conn3x\c3stable'); $k.Close(); [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKey('SOFTWARE\Conn3x\c3stable'); 'stable' } catch { $_.Exception.Message }`, nil)
	if got := strings.TrimSpace(res.Text); got != "stable" {
		t.Errorf("SOFTWARE\\Conn3x: %s", got)
	}
}

func TestPackageFromURL(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	p := windows.Package{ProductCode: sevenZipCode, URL: sevenZipURL, SHA256: sevenZipSum}
	t.Cleanup(func() { _, _ = windows.ApplyPackage(context.Background(), c, windows.Package{ProductCode: sevenZipCode, Absent: true}, 10*time.Minute) })
	if _, err := windows.ApplyPackage(ctx, c, p, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	if ok, _ := windows.PackageInstalled(ctx, c, sevenZipCode); !ok {
		t.Error("7-Zip isn't listed as installed")
	}
	// The same address with one hex digit of the hash wrong installs nothing.
	if _, err := windows.ApplyPackage(ctx, c, windows.Package{ProductCode: sevenZipCode, Absent: true}, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	p.SHA256 = "f" + sevenZipSum[1:]
	if _, err := windows.ApplyPackage(ctx, c, p, 10*time.Minute); err == nil {
		t.Error("a mismatched download installed")
	}
	// A missing file says so, with its HTTP status.
	missing := windows.Package{ProductCode: sevenZipCode, URL: sevenZipURL + ".missing", SHA256: sevenZipSum}
	if _, err := windows.ApplyPackage(ctx, c, missing, 10*time.Minute); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("missing file: %v", err)
	}
	// The 1.9 MiB package is over a 1 MiB cap, and stops there.
	p.SHA256, p.MaxSizeMB = sevenZipSum, 1
	if _, err := windows.ApplyPackage(ctx, c, p, 10*time.Minute); err == nil || !strings.Contains(err.Error(), "max_size_mb") {
		t.Errorf("over the cap: %v", err)
	}
	if ok, _ := windows.PackageInstalled(ctx, c, sevenZipCode); ok {
		t.Error("installed over the cap")
	}
}

// TestPackageRebootFlow is the run that stops between an install that wants a
// reboot and the reboot step: the next plan still has the reboot.
func TestPackageRebootFlow(t *testing.T) {
	bin := os.Getenv("CONN3X_WIN_BIN")
	if bin == "" || os.Getenv("CONN3X_WIN_REBOOT") == "" {
		t.Skip("needs CONN3X_WIN_BIN and CONN3X_WIN_REBOOT")
	}
	c := connect(t)
	m := buildMSI(t, c, tempDir(t, c), true)
	dir := t.TempDir()
	key := env(t, "CONN3X_WIN_KEY")
	if abs, err := filepath.Abs(key); err == nil {
		key = abs
	}
	write := func(boom bool) {
		t.Helper()
		fail := ""
		if boom {
			fail = `
  step "boom" {
    windows_powershell {
      script  = "throw 'stopped on purpose'"
      creates = "C:\\conn3x-never-there"
    }
  }`
		}
		src := fmt.Sprintf(`
circuit "win" {
  hosts = { vm = %[1]q }
  ssh {
    user             = %[2]q
    private_key_file = %[3]q
    host_key         = %[4]q
    become           = true
  }
  step "pkg" {
    windows_package {
      product_code = %[5]q
      source       = %[6]q
      sha256       = %[7]q
    }
  }%[8]s
  step "restart_if_needed" {
    windows_reboot {
      only_if_pending = true
    }
  }
}
`, env(t, "CONN3X_WIN_HOST"), env(t, "CONN3X_WIN_USER"), key, env(t, "CONN3X_WIN_HOST_KEY"), m.Code, m.Path, m.SHA256, fail)
		if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tool := func(args ...string) (string, int) {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return string(out), ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return string(out), 0
	}
	write(true)
	if out, code := tool("init", "-no-color"); code != 0 {
		t.Fatal(out)
	}
	// First run: the install asks for a reboot, then the run stops.
	if out, code := tool("apply", "-no-color", "-input=false", "-auto-approve"); code == 0 || !strings.Contains(out, "stopped on purpose") {
		t.Fatalf("apply: exit %d\n%s", code, out)
	}
	if ok, _ := windows.PackageInstalled(context.Background(), c, m.Code); !ok {
		t.Fatal("the package didn't install")
	}
	// The next plan has the reboot that was missed.
	write(false)
	out, code := tool("plan", "-no-color", "-input=false", "-detailed-exitcode")
	if code != 2 || !strings.Contains(out, "restart_if_needed") {
		t.Fatalf("plan after the stopped run: exit %d\n%s", code, out)
	}
	boot, _ := windows.BootID(context.Background(), c)
	if out, code := tool("apply", "-no-color", "-input=false", "-auto-approve"); code != 0 {
		t.Fatalf("apply: exit %d\n%s", code, out)
	}
	c = connect(t)
	if after, _ := windows.BootID(context.Background(), c); after == boot {
		t.Error("no reboot happened")
	}
	if pending, _ := windows.PendingReboot(context.Background(), c); pending {
		t.Error("still pending after the reboot")
	}
	if out, code := tool("plan", "-no-color", "-input=false", "-detailed-exitcode"); code != 0 {
		t.Errorf("plan after the reboot: exit %d\n%s", code, out)
	}
}
