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
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// ruleName is a fresh rule name, whose rule is removed when the test ends.
func ruleName(t *testing.T, c *ssh.Client) string {
	t.Helper()
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	name := "Conn3x test " + hex.EncodeToString(b)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = windows.ApplyFirewallRuleRemove(ctx, c, name)
	})
	return name
}

// ruleCount is how many rules the host has, and a hash of them.
func ruleCount(t *testing.T, c *ssh.Client) string {
	t.Helper()
	return strings.TrimSpace(run(t, c, `$all = Get-NetFirewallRule | Sort-Object Name | ForEach-Object { "$($_.Name)|$($_.Enabled)|$($_.Action)" }
$sum = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes(($all -join "`+"`n"+`")))
"$($all.Count) $([BitConverter]::ToString($sum))"`, nil).Text)
}

func TestFirewallRules(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	name := ruleName(t, c)
	desc := `'; $(md c3mark) %PATH%`
	f := windows.FirewallRule{
		Name: name, DisplayName: `Conn3x "test" $(x)`, Description: &desc, Protocol: "tcp",
		LocalPorts: []string{"8443", "9000-9010"}, RemoteAddresses: []string{"10.0.0.0/8", "192.0.2.7", "198.51.100.1-198.51.100.9", "2001:db8::/32"},
		Profiles: []string{"domain", "private"}, Enabled: true,
	}.WithDefaults()
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	a, err := windows.ReadFirewallRule(ctx, c, name)
	if err != nil || a.Exists || f.Matches(a) {
		t.Fatalf("before: %+v, %v", a, err)
	}
	if err := windows.ApplyFirewallRule(ctx, c, f); err != nil {
		t.Fatal(err)
	}
	if a, err = windows.ReadFirewallRule(ctx, c, name); err != nil || !f.Matches(a) {
		t.Fatalf("after: %+v, %v", a, err)
	}
	t.Logf("as Windows reports it: %+v", a)

	// Each change is drift, and applying again sets it back.
	for what, change := range map[string]string{
		"disabled": `Set-NetFirewallRule -Name $A.n -Enabled False`,
		"port":     `Set-NetFirewallRule -Name $A.n -LocalPort 8443`,
		"address":  `Set-NetFirewallRule -Name $A.n -RemoteAddress Any`,
		"action":   `Set-NetFirewallRule -Name $A.n -Action Block`,
		"profile":  `Set-NetFirewallRule -Name $A.n -Profile Public`,
	} {
		run(t, c, "param($A) "+change, map[string]any{"n": name})
		if a, _ = windows.ReadFirewallRule(ctx, c, name); f.Matches(a) {
			t.Errorf("%s: drift matched", what)
		}
		if err := windows.ApplyFirewallRule(ctx, c, f); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if a, _ = windows.ReadFirewallRule(ctx, c, name); !f.Matches(a) {
			t.Errorf("%s: not put back: %+v", what, a)
		}
	}

	// From TCP with ports to ICMP, which has none.
	icmp := windows.FirewallRule{Name: name, Protocol: "icmpv4", Action: "block", Enabled: true}.WithDefaults()
	if err := windows.ApplyFirewallRule(ctx, c, icmp); err != nil {
		t.Fatal(err)
	}
	if a, _ = windows.ReadFirewallRule(ctx, c, name); !icmp.Matches(a) {
		t.Errorf("icmp: %+v", a)
	}

	if err := windows.ApplyFirewallRuleRemove(ctx, c, name); err != nil {
		t.Fatal(err)
	}
	if a, _ = windows.ReadFirewallRule(ctx, c, name); a.Exists {
		t.Error("remove left the rule")
	}
	if err := windows.ApplyFirewallRuleRemove(ctx, c, name); err != nil {
		t.Errorf("removing it twice: %v", err)
	}

	// Hostile names never reach a host as anything but a name, and reads
	// change no rule.
	before := ruleCount(t, c)
	for label, v := range hostile {
		if (windows.FirewallRule{Name: v}).WithDefaults().Validate() == nil {
			if a, err := windows.ReadFirewallRule(ctx, c, v); err != nil || a.Exists {
				t.Errorf("%s: %+v, %v", label, a, err)
			}
		}
	}
	for range 3 {
		if _, err := windows.ReadFirewallRule(ctx, c, "OpenSSH-Server-In-TCP"); err != nil {
			t.Fatal(err)
		}
	}
	if after := ruleCount(t, c); after != before {
		t.Errorf("reads changed rules: %s to %s", before, after)
	}
	if got := strings.TrimSpace(run(t, c, `(Test-Path -LiteralPath 'C:\marker') -or (Test-Path -LiteralPath (Join-Path $HOME 'c3mark'))`, nil).Text); got != "False" {
		t.Error("a hostile value ran")
	}
}

// TestFirewallRuleFlow is plan, apply, drift and removal through the binary.
func TestFirewallRuleFlow(t *testing.T) {
	bin := os.Getenv("CONN3X_WIN_BIN")
	if bin == "" {
		t.Skip("CONN3X_WIN_BIN is not set")
	}
	c := connect(t)
	name := ruleName(t, c)
	dir := t.TempDir()
	key := env(t, "CONN3X_WIN_KEY")
	if abs, err := filepath.Abs(key); err == nil {
		key = abs
	}
	write := func(step string) {
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
`, env(t, "CONN3X_WIN_HOST"), env(t, "CONN3X_WIN_USER"), key, env(t, "CONN3X_WIN_HOST_KEY"), step)
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
	plan := func(want int) {
		t.Helper()
		if out, code := tool("plan", "-no-color", "-input=false", "-detailed-exitcode"); code != want {
			t.Fatalf("plan: exit %d, want %d\n%s", code, want, out)
		}
	}
	apply := func() {
		t.Helper()
		if out, code := tool("apply", "-no-color", "-input=false", "-auto-approve"); code != 0 {
			t.Fatalf("apply: exit %d\n%s", code, out)
		}
	}
	write(fmt.Sprintf(`step "web" {
    windows_firewall_rule {
      name             = %q
      protocol         = "tcp"
      local_ports      = ["8443"]
      remote_addresses = ["10.0.0.0/8"]
    }
  }`, name))
	if out, code := tool("init", "-no-color"); code != 0 {
		t.Fatal(out)
	}
	plan(2)
	apply()
	plan(0)
	run(t, c, `param($A) Set-NetFirewallRule -Name $A.n -Enabled False`, map[string]any{"n": name})
	plan(2)
	apply()
	plan(0)
	// A rule that would block SSH is refused before anything connects.
	write(`step "nope" {
    windows_firewall_rule {
      name   = "Conn3x block all"
      action = "block"
    }
  }`)
	if out, code := tool("plan", "-no-color", "-input=false"); code == 0 || !strings.Contains(out, "cuts Conn3x off") {
		t.Errorf("a rule blocking SSH: exit %d\n%s", code, out)
	}
	// Removing the step deletes the rule.
	write("")
	apply()
	if a, err := windows.ReadFirewallRule(context.Background(), c, name); err != nil || a.Exists {
		t.Errorf("after removing the step: %+v, %v", a, err)
	}

	// The host says which connection this is.
	ctx := context.Background()
	conn, err := windows.ReadSSHConn(ctx, c, 0)
	if err != nil || !conn.Client.IsValid() || conn.Port == 0 {
		t.Fatalf("SSH_CONNECTION: %+v, %v", conn, err)
	}
	t.Logf("connection as the host sees it: %s", conn)
	fail := func(want string) {
		t.Helper()
		out, code := tool("apply", "-no-color", "-input=false", "-auto-approve")
		if code == 0 || !strings.Contains(out, want) {
			t.Fatalf("apply: exit %d, want an error with %q\n%s", code, want, out)
		}
	}

	// A block that names only this client passes the plan-time check, and
	// apply refuses it before the rule exists.
	write(fmt.Sprintf(`step "block_me" {
    windows_firewall_rule {
      name             = %q
      action           = "block"
      protocol         = "tcp"
      local_ports      = ["%d"]
      remote_addresses = [%q]
    }
  }`, name, conn.Port, conn.Client.String()))
	plan(2)
	fail("the connection Conn3x is using")
	if a, _ := windows.ReadFirewallRule(ctx, c, name); a.Exists {
		t.Error("the blocking rule was made")
	}

	// The rule that lets SSH in can be adopted without renaming it, but not
	// narrowed or deleted.
	const ssh = "OpenSSH-Server-In-TCP"
	orig, err := windows.ReadFirewallRule(ctx, c, ssh)
	if err != nil || !orig.Exists || !orig.Rule().AllowsSSH(conn) {
		t.Skipf("no %s rule letting this connection in here (%+v, %v)", ssh, orig, err)
	}
	adopt := func(extra string) string {
		return fmt.Sprintf(`step "sshd" {
    windows_firewall_rule {
      name        = %q
      protocol    = "tcp"
      local_ports = %q
      %s
    }
  }`, ssh, orig.LocalPorts, extra)
	}
	write(adopt(""))
	apply()
	plan(0)
	if a, _ := windows.ReadFirewallRule(ctx, c, ssh); a.DisplayName != orig.DisplayName {
		t.Errorf("adopting renamed it: %q to %q", orig.DisplayName, a.DisplayName)
	}
	for what, extra := range map[string]string{
		"narrowed": `remote_addresses = ["192.0.2.0/24"]`,
		"disabled": `enabled = false`,
		"profile":  `profiles = ["domain"]`,
	} {
		write(adopt(extra))
		out, code := tool("apply", "-no-color", "-input=false", "-auto-approve")
		if code == 0 || !strings.Contains(out, "would stop it") {
			t.Errorf("%s: exit %d\n%s", what, code, out)
		}
	}
	write("")
	fail("deleting it could cut Conn3x off")
	if a, _ := windows.ReadFirewallRule(ctx, c, ssh); !a.Exists || !orig.Rule().AllowsSSH(conn) || !a.Rule().AllowsSSH(conn) {
		t.Fatalf("the SSH rule changed: %+v", a)
	}
	write(adopt(`on_remove = "forget"`))
	apply()
	write("")
	apply()
	if a, _ := windows.ReadFirewallRule(ctx, c, ssh); !a.Exists {
		t.Error("forget deleted the SSH rule")
	}
	if !connect(t).Alive() {
		t.Error("the connection is gone")
	}
}
