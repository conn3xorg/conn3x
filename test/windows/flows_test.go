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
)

// flow runs the conn3x binary on one circuit against the runner, for the
// whole cycle a module goes through: plan, apply, drift, apply again.
type flow struct {
	t   *testing.T
	bin string
	dir string
}

func newFlow(t *testing.T) *flow {
	t.Helper()
	bin := os.Getenv("CONN3X_WIN_BIN")
	if bin == "" {
		t.Skip("CONN3X_WIN_BIN is not set")
	}
	return &flow{t: t, bin: bin, dir: t.TempDir()}
}

// write puts steps in the circuit, which logs in as the other tests do.
func (f *flow) write(steps string) {
	f.t.Helper()
	key := env(f.t, "CONN3X_WIN_KEY")
	if abs, err := filepath.Abs(key); err == nil {
		key = abs
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
  %[5]s
}
`, env(f.t, "CONN3X_WIN_HOST"), env(f.t, "CONN3X_WIN_USER"), key, env(f.t, "CONN3X_WIN_HOST_KEY"), steps)
	if err := os.WriteFile(filepath.Join(f.dir, "main.tf"), []byte(src), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *flow) tool(args ...string) (string, int) {
	f.t.Helper()
	cmd := exec.Command(f.bin, args...)
	cmd.Dir = f.dir
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(out), ee.ExitCode()
	} else if err != nil {
		f.t.Fatal(err)
	}
	return string(out), 0
}

func (f *flow) expect(want int, args ...string) string {
	f.t.Helper()
	out, code := f.tool(append(args, "-no-color", "-input=false")...)
	if code != want {
		f.t.Fatalf("%s: exit %d, want %d\n%s", args[0], code, want, out)
	}
	return out
}

// cycle applies the steps, checks the next plan is empty, makes a change by
// hand, and checks drift names it and apply puts it back.
func (f *flow) cycle(steps string, change func()) {
	f.t.Helper()
	f.write(steps)
	f.expect(0, "init")
	f.expect(2, "plan", "-detailed-exitcode")
	f.expect(0, "apply", "-auto-approve")
	f.expect(0, "plan", "-detailed-exitcode")
	change()
	f.expect(2, "drift")
	f.expect(0, "apply", "-auto-approve")
	f.expect(0, "plan", "-detailed-exitcode")
}

func suffix() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Spooler is on every runner. Its start mode and state are put back however
// the test ends.
func TestServiceFlow(t *testing.T) {
	f := newFlow(t)
	c := connect(t)
	orig := strings.TrimSpace(run(t, c, `$s = Get-Service Spooler; "$($s.StartType)|$($s.Status)"`, nil).Text)
	t.Cleanup(func() {
		mode, state, _ := strings.Cut(orig, "|")
		run(t, c, `param($A) Set-Service Spooler -StartupType $A.mode; if ($A.state -eq 'Running') { Start-Service Spooler } else { Stop-Service Spooler -Force }`,
			map[string]any{"mode": mode, "state": state})
	})
	f.cycle(`step "spooler" {
    windows_service {
      name       = "Spooler"
      start_mode = "manual"
      state      = "stopped"
    }
  }`, func() {
		run(t, c, `Set-Service Spooler -StartupType Automatic; Start-Service Spooler`, nil)
	})
	if got := strings.TrimSpace(run(t, c, `$s = Get-Service Spooler; "$($s.StartType)|$($s.Status)"`, nil).Text); got != "Manual|Stopped" {
		t.Errorf("Spooler after the last apply: %s", got)
	}
}

func TestRegistryValueFlow(t *testing.T) {
	f := newFlow(t)
	c := connect(t)
	sub := "Conn3xTest" + suffix()
	regCleanup(t, c, `SOFTWARE\`+sub)
	f.cycle(fmt.Sprintf(`step "mode" {
    windows_registry_value {
      key  = "HKLM\\SOFTWARE\\%s"
      name = "Mode"
      type = "string"
      data = "on"
    }
  }`, sub), func() {
		run(t, c, `param($A) Set-ItemProperty -LiteralPath ('HKLM:\SOFTWARE\' + $A.sub) -Name Mode -Value off`, map[string]any{"sub": sub})
	})
	if got := strings.TrimSpace(run(t, c, `param($A) (Get-ItemProperty -LiteralPath ('HKLM:\SOFTWARE\' + $A.sub)).Mode`, map[string]any{"sub": sub}).Text); got != "on" {
		t.Errorf("Mode after the last apply: %q", got)
	}
}

func TestAclFlow(t *testing.T) {
	f := newFlow(t)
	c := connect(t)
	dir := tempDir(t, c)
	f.cycle(fmt.Sprintf(`step "uploads" {
    windows_acl {
      path = %q

      entry {
        principal = "BUILTIN\\Users"
        rights    = ["Modify"]
      }
    }
  }`, dir), func() {
		run(t, c, `param($A) icacls $A.dir /remove:g 'BUILTIN\Users' | Out-Null`, map[string]any{"dir": dir})
	})
	if got := run(t, c, `param($A) (Get-Acl -LiteralPath $A.dir).Access | Where-Object { $_.IdentityReference -eq 'BUILTIN\Users' -and -not $_.IsInherited } | ForEach-Object { "$($_.FileSystemRights)" }`, map[string]any{"dir": dir}).Text; !strings.Contains(got, "Modify") {
		t.Errorf("Users after the last apply: %q", got)
	}
}

// Installing on a CI runner is slow and pointless, so only the read side
// runs: what's waiting, and a plan that would install it.
func TestUpdateReadOnly(t *testing.T) {
	c := connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	u := windows.Update{Categories: []string{"DefinitionUpdates"}}
	pending, err := windows.PendingUpdates(ctx, c, u)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("waiting definition updates: %q", pending)
	for _, p := range pending {
		if !strings.HasPrefix(p, "KB") {
			t.Errorf("%q doesn't start with its KB number", p)
		}
	}

	f := newFlow(t)
	f.write(`step "definitions" {
    windows_update {
      categories = ["DefinitionUpdates"]
    }
  }`)
	f.expect(0, "init")
	out := f.expect(2, "plan", "-detailed-exitcode")
	if !strings.Contains(out, "conn3x_windows_update.win__definitions") {
		t.Errorf("the plan doesn't name the step:\n%s", out)
	}
	// A new step's plan says what its apply would install, read from the
	// host, though the step has never been applied.
	if !strings.Contains(out, "the apply installs these") && !strings.Contains(out, "no updates wait in these categories") {
		t.Errorf("the plan of a new step doesn't say what it installs:\n%s", out)
	}
	for _, p := range pending {
		if kb := strings.Fields(p)[0]; !strings.Contains(out, kb) {
			t.Logf("%s was waiting before the plan and isn't in it; it may have installed in between", kb)
		}
	}
}
