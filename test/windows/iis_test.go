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
	"io"
	"net/http"
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

// iisNames are a fresh pool and site name, removed when the test ends.
func iisNames(t *testing.T, c *ssh.Client) (pool, site string) {
	t.Helper()
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	pool, site = "c3pool "+hex.EncodeToString(b), "c3site "+hex.EncodeToString(b)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = windows.ApplySiteRemove(ctx, c, site)
		_ = windows.ApplyAppPoolRemove(ctx, c, pool)
	})
	return pool, site
}

// siteFolder makes a folder under C:\ and removes it afterwards. Admin-only,
// with read for the pools and anonymous visitors. "open": Authenticated Users
// may also change it, as a new folder under C:\ allows on the Azure image.
// "files": Users may change what's inside, through a rule that skips the
// folder itself.
func siteFolder(t *testing.T, c *ssh.Client, mode string) string {
	t.Helper()
	d := `C:\c3iis-` + randHex(4)
	run(t, c, `param($A)
$sec = New-Object Security.AccessControl.DirectorySecurity
$sec.SetAccessRuleProtection($true, $false)
foreach ($s in 'S-1-5-18', 'S-1-5-32-544') { $sec.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(([Security.Principal.SecurityIdentifier]$s), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))) }
foreach ($s in 'S-1-5-32-568', 'S-1-5-17') { $sec.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(([Security.Principal.SecurityIdentifier]$s), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))) }
if ($A.mode -eq 'files') { $sec.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(([Security.Principal.SecurityIdentifier]'S-1-5-32-545'), 'Modify', 'ContainerInherit,ObjectInherit', 'InheritOnly', 'Allow'))) }
if ($A.mode -eq 'open') { $sec.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(([Security.Principal.SecurityIdentifier]'S-1-5-11'), 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))) }
[void][IO.Directory]::CreateDirectory($A.d, $sec)`, map[string]any{"d": d, "mode": mode})
	t.Cleanup(func() {
		_, _ = ps.User(context.Background(), c, `param($A) if ([IO.Directory]::Exists($A.d)) { [IO.Directory]::Delete($A.d, $true) }`, map[string]any{"d": d}, time.Minute)
	})
	return d
}

// iisConfig is a hash of IIS's configuration, so a read that wrote it shows.
func iisConfig(t *testing.T, c *ssh.Client) string {
	t.Helper()
	return strings.TrimSpace(run(t, c, `$f = $env:windir + '\System32\inetsrv\config\applicationHost.config'
if (Test-Path -LiteralPath $f) { (Get-FileHash -LiteralPath $f).Hash + ' ' + (Get-Item -LiteralPath $f).LastWriteTimeUtc.Ticks } else { 'none' }`, nil).Text)
}

// installIIS reads a pool and a site on a host without IIS, which must say
// absent, then installs Web-Server. With IIS already there, it only checks.
func installIIS(t *testing.T, c *ssh.Client) {
	t.Helper()
	ctx := context.Background()
	if iisConfig(t, c) == "none" {
		p, err := windows.ReadAppPool(ctx, c, "DefaultAppPool")
		if err != nil || p.Installed || p.Exists {
			t.Fatalf("pool without IIS: %+v, %v", p, err)
		}
		s, err := windows.ReadSite(ctx, c, "Default Web Site")
		if err != nil || s.Installed || s.Exists {
			t.Fatalf("site without IIS: %+v, %v", s, err)
		}
		if err := windows.ApplySite(ctx, c, windows.Site{Name: "x", PhysicalPath: `C:\x`, Bindings: []windows.Binding{{Protocol: "http", IP: "*", Port: 80}}}); err == nil || !strings.Contains(err.Error(), "IIS is not installed") {
			t.Errorf("site apply without IIS: %v", err)
		}
		t.Log("without IIS, reads are absent and apply says why")
		restart, err := windows.ApplyFeature(ctx, c, windows.Feature{Name: "Web-Server"}, 15*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Web-Server installed, restart needed: %v", restart)
	}
	t.Logf("modules on the host: %s", strings.TrimSpace(run(t, c, `(Get-Module -ListAvailable WebAdministration, IISAdministration | ForEach-Object { "$($_.Name) $($_.Version)" }) -join ', '`, nil).Text))
}

func TestIIS(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	installIIS(t, c)
	poolName, siteName := iisNames(t, c)
	dir := siteFolder(t, c, "")

	p := windows.AppPool{Name: poolName, Started: true, RuntimeVersion: "", PipelineMode: "classic", Identity: "NetworkService"}
	if a, err := windows.ReadAppPool(ctx, c, poolName); err != nil || !a.Installed || a.Exists {
		t.Fatalf("pool before: %+v, %v", a, err)
	}
	if err := windows.ApplyAppPool(ctx, c, p); err != nil {
		t.Fatal(err)
	}
	a, err := windows.ReadAppPool(ctx, c, poolName)
	if err != nil || !p.Matches(a) {
		t.Fatalf("pool after: %+v, %v", a, err)
	}
	t.Logf("pool as IIS reports it: %+v", a)

	s := windows.Site{Name: siteName, PhysicalPath: dir, AppPool: poolName, Started: true, Bindings: []windows.Binding{
		{Protocol: "http", IP: "*", Port: 8091, HostHeader: "c3.example.com"},
		{Protocol: "http", IP: "127.0.0.1", Port: 8092},
	}}
	if err := windows.ApplySite(ctx, c, s); err != nil {
		t.Fatal(err)
	}
	sa, err := windows.ReadSite(ctx, c, siteName)
	if err != nil || !s.Matches(sa) {
		t.Fatalf("site after: %+v, %v", sa, err)
	}
	t.Logf("site as IIS reports it: %+v", sa)

	// Each hand change is drift, and applying again puts it back.
	for what, change := range map[string]string{
		"pool stopped":  `Stop-WebAppPool -Name $A.p`,
		"pool runtime":  `Set-ItemProperty -LiteralPath ('IIS:\AppPools\' + $A.p) -Name managedRuntimeVersion -Value v4.0`,
		"pool identity": `Set-ItemProperty -LiteralPath ('IIS:\AppPools\' + $A.p) -Name processModel.identityType -Value LocalService`,
	} {
		run(t, c, "param($A) Import-Module WebAdministration; "+change, map[string]any{"p": poolName})
		if a, _ = windows.ReadAppPool(ctx, c, poolName); p.Matches(a) {
			t.Errorf("%s: drift matched", what)
		}
		if err := windows.ApplyAppPool(ctx, c, p); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if a, _ = windows.ReadAppPool(ctx, c, poolName); !p.Matches(a) {
			t.Errorf("%s: not put back: %+v", what, a)
		}
	}
	for what, change := range map[string]string{
		"site stopped":  `Stop-Website -Name $A.s`,
		"extra binding": `New-WebBinding -Name $A.s -Protocol http -Port 8093`,
		"path":          `Set-ItemProperty -LiteralPath ('IIS:\Sites\' + $A.s) -Name physicalPath -Value 'C:\Windows\Temp'`,
		"pool":          `Set-ItemProperty -LiteralPath ('IIS:\Sites\' + $A.s) -Name applicationPool -Value DefaultAppPool`,
	} {
		run(t, c, "param($A) Import-Module WebAdministration; "+change, map[string]any{"s": siteName})
		if sa, _ = windows.ReadSite(ctx, c, siteName); s.Matches(sa) {
			t.Errorf("%s: drift matched", what)
		}
		if err := windows.ApplySite(ctx, c, s); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if sa, _ = windows.ReadSite(ctx, c, siteName); !s.Matches(sa) {
			t.Errorf("%s: not put back: %+v", what, sa)
		}
	}

	// Stopped stays stopped, and doesn't start with IIS.
	p.Started, s.Started = false, false
	if err := windows.ApplySite(ctx, c, s); err != nil {
		t.Fatal(err)
	}
	if err := windows.ApplyAppPool(ctx, c, p); err != nil {
		t.Fatal(err)
	}
	if a, _ = windows.ReadAppPool(ctx, c, poolName); !p.Matches(a) || a.AutoStart {
		t.Errorf("stopped pool: %+v", a)
	}
	if sa, _ = windows.ReadSite(ctx, c, siteName); !s.Matches(sa) || sa.AutoStart {
		t.Errorf("stopped site: %+v", sa)
	}

	// A site that can't start says so.
	clash := windows.Site{Name: siteName + "b", PhysicalPath: dir, Started: true, Bindings: []windows.Binding{{Protocol: "http", IP: "127.0.0.1", Port: 8094}}}
	t.Cleanup(func() { _ = windows.ApplySiteRemove(context.Background(), c, clash.Name) })
	other := s
	other.Started, other.Bindings = true, clash.Bindings
	if err := windows.ApplySite(ctx, c, other); err != nil {
		t.Fatal(err)
	}
	if err := windows.ApplySite(ctx, c, clash); err == nil || !strings.Contains(err.Error(), "not Started") {
		t.Errorf("clashing binding: %v", err)
	}

	// A folder others can change is refused, whoever the pool runs as, and
	// so is one that isn't there.
	before := iisConfig(t, c)
	for what, path := range map[string]string{"open": siteFolder(t, c, "open"), "files": siteFolder(t, c, "files"), "missing": `C:\c3iis-missing-` + randHex(4)} {
		bad := s
		bad.PhysicalPath = path
		if err := windows.ApplySite(ctx, c, bad); err == nil || !strings.Contains(err.Error(), map[string]string{"open": "S-1-5-11 can", "files": "S-1-5-32-545 can add or replace files", "missing": "doesn't exist"}[what]) {
			t.Errorf("%s folder: %v", what, err)
		}
	}
	if after := iisConfig(t, c); after != before {
		t.Error("a refused folder still wrote the configuration")
	}

	// Changing a pool's identity checks every folder its sites serve, made
	// by Conn3x or not.
	hand := siteName + "h"
	open := siteFolder(t, c, "files")
	t.Cleanup(func() { _ = windows.ApplySiteRemove(context.Background(), c, hand) })
	run(t, c, `param($A) Import-Module WebAdministration; New-Website -Name $A.s -PhysicalPath $A.d -Port 8095 -IPAddress 127.0.0.1 -ApplicationPool $A.p | Out-Null`, map[string]any{"s": hand, "d": open, "p": poolName})
	sys := p
	sys.Identity = "LocalSystem"
	if err := windows.ApplyAppPool(ctx, c, sys); err == nil || !strings.Contains(err.Error(), "S-1-5-32-545 can") || !strings.Contains(err.Error(), open) {
		t.Errorf("identity switch over an open folder: %v", err)
	}
	if a, _ = windows.ReadAppPool(ctx, c, poolName); a.Identity != p.Identity {
		t.Errorf("the identity changed anyway: %+v", a)
	}
	if err := windows.ApplySiteRemove(ctx, c, hand); err != nil {
		t.Fatal(err)
	}

	// A missing pool is refused before anything is written.
	before = iisConfig(t, c)
	missing := s
	missing.AppPool = "c3 no such pool"
	if err := windows.ApplySite(ctx, c, missing); err == nil || !strings.Contains(err.Error(), "doesn't exist") {
		t.Errorf("missing pool: %v", err)
	}
	if after := iisConfig(t, c); after != before {
		t.Error("a refused site still wrote the configuration")
	}

	// Hostile names never get past validation, and reads change nothing.
	before = iisConfig(t, c)
	snap := snapshot(t, c, "")
	for label, v := range hostile {
		if (windows.AppPool{Name: v, RuntimeVersion: "v4.0", PipelineMode: "integrated", Identity: "ApplicationPoolIdentity"}).Validate() == nil {
			t.Errorf("%s: a hostile pool name passed", label)
		}
	}
	for range 3 {
		if _, err := windows.ReadAppPool(ctx, c, "DefaultAppPool"); err != nil {
			t.Fatal(err)
		}
		if _, err := windows.ReadSite(ctx, c, "Default Web Site"); err != nil {
			t.Fatal(err)
		}
		if _, err := windows.ReadSite(ctx, c, "c3 never made"); err != nil {
			t.Fatal(err)
		}
	}
	compare(t, snap, snapshot(t, c, ""))
	if after := iisConfig(t, c); after != before {
		t.Errorf("reads changed applicationHost.config: %s to %s", before, after)
	}

	for _, rm := range []func() error{
		func() error { return windows.ApplySiteRemove(ctx, c, siteName) },
		func() error { return windows.ApplyAppPoolRemove(ctx, c, poolName) },
		func() error { return windows.ApplySiteRemove(ctx, c, siteName) },
	} {
		if err := rm(); err != nil {
			t.Fatal(err)
		}
	}
	if sa, _ = windows.ReadSite(ctx, c, siteName); sa.Exists {
		t.Error("remove left the site")
	}
	if a, _ = windows.ReadAppPool(ctx, c, poolName); a.Exists {
		t.Error("remove left the pool")
	}
	if got := strings.TrimSpace(run(t, c, `param($A) Test-Path -LiteralPath $A.d`, map[string]any{"d": dir}).Text); got != "True" {
		t.Error("removing the site removed its files")
	}
}

// TestIISFlow is the whole thing through the binary: IIS installed, a pool
// and a site serving a page on port 80, opened in the firewall, then drift
// and removal.
func TestIISFlow(t *testing.T) {
	bin := os.Getenv("CONN3X_WIN_BIN")
	if bin == "" {
		t.Skip("CONN3X_WIN_BIN is not set")
	}
	c := connect(t)
	ctx := context.Background()
	poolName, siteName := iisNames(t, c)
	// Made by the circuit, as the site page shows: admin-only from the start.
	page := `C:\inetpub\` + strings.ReplaceAll(siteName, " ", "-")
	t.Cleanup(func() {
		_, _ = ps.User(context.Background(), c, `param($A) if ([IO.Directory]::Exists($A.d)) { [IO.Directory]::Delete($A.d, $true) }`, map[string]any{"d": page}, time.Minute)
	})
	rule := ruleName(t, c)
	dir := t.TempDir()
	key := env(t, "CONN3X_WIN_KEY")
	if abs, err := filepath.Abs(key); err == nil {
		key = abs
	}
	write := func(steps string) {
		t.Helper()
		src := fmt.Sprintf(`
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
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return string(out), ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return string(out), 0
	}
	plan := func(want int) string {
		t.Helper()
		out, code := tool("plan", "-no-color", "-input=false", "-detailed-exitcode")
		if code != want {
			t.Fatalf("plan: exit %d, want %d\n%s", code, want, out)
		}
		return out
	}
	apply := func() {
		t.Helper()
		if out, code := tool("apply", "-no-color", "-input=false", "-auto-approve"); code != 0 {
			t.Fatalf("apply: exit %d\n%s", code, out)
		}
	}
	// Web-Server includes static content on a fresh install, but an image
	// with IIS already on, like the runner's, may not: then IIS answers 200
	// with an empty body.
	steps := fmt.Sprintf(`step "iis" {
    windows_feature {
      name = "Web-Server"
    }
  }
  step "static" {
    windows_feature {
      name = "Web-Static-Content"
    }
  }
  step "site_folder" {
    windows_directory {
      path = %[3]q
      acl {
        principal = "S-1-5-32-544"
        rights    = ["FullControl"]
      }
      acl {
        principal = "S-1-5-18"
        rights    = ["FullControl"]
      }
      acl {
        principal = "S-1-5-32-568"
        rights    = ["ReadAndExecute"]
      }
      acl {
        principal = "S-1-5-17"
        rights    = ["ReadAndExecute"]
      }
    }
  }
  step "page" {
    windows_file {
      path    = %[5]q
      content = "hello from conn3x"
    }
  }
  step "pool" {
    windows_iis_app_pool {
      name                    = %[1]q
      managed_runtime_version = ""
    }
  }
  step "site" {
    windows_iis_site {
      name          = %[2]q
      physical_path = %[3]q
      app_pool      = %[1]q
      binding {
        port        = 80
        host_header = "conn3x.test"
      }
    }
  }
  step "http_in" {
    windows_firewall_rule {
      name        = %[4]q
      protocol    = "tcp"
      local_ports = ["80"]
    }
  }`, poolName, siteName, page, rule, page+`\index.html`)
	write(steps)
	if out, code := tool("init", "-no-color"); code != 0 {
		t.Fatal(out)
	}
	plan(2)
	apply()
	plan(0)

	get := func() (int, string) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+env(t, "CONN3X_WIN_HOST")+"/index.html", nil)
		req.Host = "conn3x.test"
		resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		// One Read can come back short, empty even, on loopback.
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return resp.StatusCode, string(b)
	}
	// Installing IIS opens port 80 with its own rule; turned off, the page
	// can only come through the step's.
	const iisRule = "IIS-WebServerRole-HTTP-In-TCP"
	run(t, c, `param($A) Disable-NetFirewallRule -Name $A.r`, map[string]any{"r": iisRule})
	t.Cleanup(func() {
		_, _ = ps.User(context.Background(), c, `param($A) Enable-NetFirewallRule -Name $A.r`, map[string]any{"r": iisRule}, time.Minute)
	})
	if code, body := get(); code != 200 || body != "hello from conn3x" {
		t.Fatalf("page: %d %q", code, body)
	}
	t.Log("page served on port 80 through the firewall rule")

	// A hand change shows as drift, and apply puts it back.
	run(t, c, `param($A) Import-Module WebAdministration; Stop-Website -Name $A.s; Stop-WebAppPool -Name $A.p`, map[string]any{"s": siteName, "p": poolName})
	if code, _ := get(); code == 200 {
		t.Error("still served with the site stopped")
	}
	if out, code := tool("drift", "-no-color"); code != 2 {
		t.Errorf("drift: exit %d\n%s", code, out)
	}
	out := plan(2)
	if !strings.Contains(out, "windows_iis_site") || !strings.Contains(out, "windows_iis_app_pool") {
		t.Errorf("plan doesn't name both:\n%s", out)
	}
	apply()
	plan(0)
	if code, body := get(); code != 200 || body != "hello from conn3x" {
		t.Errorf("page after reapply: %d %q", code, body)
	}

	// Removing the steps deletes the site and the pool, not the files.
	write(`step "iis" {
    windows_feature {
      name = "Web-Server"
    }
  }`)
	apply()
	if s, err := windows.ReadSite(ctx, c, siteName); err != nil || s.Exists {
		t.Errorf("site after removal: %+v, %v", s, err)
	}
	if p, err := windows.ReadAppPool(ctx, c, poolName); err != nil || p.Exists {
		t.Errorf("pool after removal: %+v, %v", p, err)
	}
	if got := strings.TrimSpace(run(t, c, `param($A) Test-Path -LiteralPath ($A.d + '\index.html')`, map[string]any{"d": page}).Text); got != "True" {
		t.Error("removal took the files")
	}
	plan(0)
}
