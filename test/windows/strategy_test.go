// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build windowshost

package windowshost

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestRebootLockPerHost checks the reboot lock under both strategies. The
// runner is one machine, so "one" (127.0.0.1) and "two" (localhost) stand in
// for two hosts: the lock is keyed by address. A second circuit holds a 20 s
// step on "one". The reboot step on "one" takes that host's lock exclusive,
// so it waits for the hold, and the step after it can't start before the
// hold ends. Nothing is pending, so nothing reboots, but the reboot step
// holds the lock through its whole apply all the same. On "two", per_host
// carries on during the hold; lockstep waits for "one".
func TestRebootLockPerHost(t *testing.T) {
	bin := os.Getenv("CONN3X_WIN_BIN")
	if bin == "" {
		t.Skip("CONN3X_WIN_BIN is not set")
	}
	if env(t, "CONN3X_WIN_HOST") != "127.0.0.1" {
		t.Skip("needs loopback sshd, so localhost is a second name for the same host")
	}
	key := env(t, "CONN3X_WIN_KEY")
	if abs, err := filepath.Abs(key); err == nil {
		key = abs
	}
	for _, strategy := range []string{"per_host", "lockstep"} {
		t.Run(strategy, func(t *testing.T) {
			c := connect(t)
			remote := tempDir(t, c)
			dir := t.TempDir()
			src := fmt.Sprintf(`
circuit "side" {
  hosts = { one = "127.0.0.1" }
  ssh {
    user             = %[2]q
    private_key_file = %[3]q
    host_key         = %[4]q
  }
  step "hold" {
    windows_powershell {
      script  = "param($A) Set-Content -LiteralPath $A.start -Value ([DateTime]::UtcNow.Ticks); Start-Sleep -Seconds 20; Set-Content -LiteralPath $A.end -Value ([DateTime]::UtcNow.Ticks)"
      args    = { start = "%[5]s\\hold-start", end = "%[5]s\\hold-end" }
      creates = "%[5]s\\hold-end"
    }
  }
}
circuit "chain" {
  hosts    = { one = "127.0.0.1", two = "localhost" }
  strategy = %[1]q
  ssh {
    user             = %[2]q
    private_key_file = %[3]q
    host_key         = %[4]q
  }
  # Waits until the hold has started, so the reboot step meets it.
  step "ready" {
    windows_powershell {
      script  = "param($A) $d = (Get-Date).AddMinutes(2); while (-not (Test-Path -LiteralPath $A.started)) { if ((Get-Date) -gt $d) { throw 'the hold never started' }; Start-Sleep -Milliseconds 200 }; Set-Content -LiteralPath $A.path -Value 1"
      args    = { started = "%[5]s\\hold-start", path = "%[5]s\\${each.key}-ready" }
      creates = "%[5]s\\${each.key}-ready"
    }
  }
  step "restart" {
    windows_reboot {
      only_if_pending = true
    }
  }
  step "after" {
    windows_powershell {
      script  = "param($A) Set-Content -LiteralPath $A.path -Value ([DateTime]::UtcNow.Ticks)"
      args    = { path = "%[5]s\\${each.key}-after" }
      creates = "%[5]s\\${each.key}-after"
    }
  }
}
`, strategy, env(t, "CONN3X_WIN_USER"), key, env(t, "CONN3X_WIN_HOST_KEY"), strings.ReplaceAll(remote, `\`, `\\`))
			if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(src), 0o644); err != nil {
				t.Fatal(err)
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
			if out, code := tool("init", "-no-color"); code != 0 {
				t.Fatal(out)
			}
			out, code := tool("apply", "-no-color", "-input=false", "-auto-approve")
			t.Logf("apply:\n%s", out)
			if code != 0 {
				t.Fatalf("apply: exit %d", code)
			}
			at := func(name string) time.Time {
				t.Helper()
				s := strings.TrimSpace(run(t, c, `param($A) Get-Content -LiteralPath $A.p -Raw`, map[string]any{"p": remote + `\` + name}).Text)
				ticks, err := strconv.ParseInt(s, 10, 64)
				if err != nil {
					t.Fatalf("%s holds %q", name, s)
				}
				// .NET ticks are 100 ns since 0001-01-01, 62135596800 s before 1970.
				return time.Unix(ticks/1e7-62135596800, ticks%1e7*100).UTC()
			}
			end, one, two := at("hold-end"), at("one-after"), at("two-after")
			t.Logf("hold ended %s; after: one %+.1fs, two %+.1fs", end.Format(time.RFC3339Nano), one.Sub(end).Seconds(), two.Sub(end).Seconds())
			if !one.After(end) {
				t.Errorf("the step after the reboot on one ran %.1fs before the hold on one ended", end.Sub(one).Seconds())
			}
			if strategy == "per_host" && !two.Before(end) {
				t.Errorf("per_host: two waited for one's reboot step (%.1fs after the hold ended)", two.Sub(end).Seconds())
			}
			if strategy == "lockstep" && !two.After(end) {
				t.Errorf("lockstep: two didn't wait for one (%.1fs before the hold ended)", end.Sub(two).Seconds())
			}
			if out, code := tool("plan", "-no-color", "-input=false", "-detailed-exitcode"); code != 0 {
				t.Errorf("second plan: exit %d\n%s", code, out)
			}
		})
	}
}
