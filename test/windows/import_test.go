// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build windowshost

package windowshost

import (
	"fmt"
	"strings"
	"testing"
)

// Conn3x makes a firewall rule, a scheduled task and, with IIS on the
// runner, an app pool and a site; state forgets them; then the same steps
// with import = true adopt them, and the plan has nothing to change. This
// file sorts after iis_test.go, which installs IIS.
func TestImportAdoptsWhatWasMade(t *testing.T) {
	f := newFlow(t)
	c := connect(t)
	sfx := suffix()
	iis := strings.TrimSpace(run(t, c, `if (Get-Service W3SVC -ErrorAction SilentlyContinue) { 'yes' }`, nil).Text) == "yes"
	steps := func(imp bool) string {
		s := fmt.Sprintf(`step "rule" {
    import = %[1]t
    windows_firewall_rule {
      name        = "conn3x-import-%[2]s"
      protocol    = "tcp"
      local_ports = ["8097"]
    }
  }
  step "job" {
    import = %[1]t
    windows_scheduled_task {
      name              = "import-%[2]s"
      path              = "\\Conn3x\\"
      execute           = %[3]q
      arguments         = "/c exit 0"
      allow_interpreter = true
      user              = "SYSTEM"
      trigger {
        type = "daily"
        at   = "2030-01-01T03:00:00"
      }
    }
  }`, imp, sfx, cmdExe)
		if iis {
			s += fmt.Sprintf(`
  step "pool" {
    import = %[1]t
    windows_iis_app_pool {
      name = "conn3x-import-%[2]s"
    }
  }
  step "site" {
    import = %[1]t
    windows_iis_site {
      name          = "conn3x-import-%[2]s"
      physical_path = "C:\\inetpub\\wwwroot"
      app_pool      = "conn3x-import-%[2]s"
      binding {
        port        = 8097
        host_header = "import.conn3x.test"
      }
    }
  }`, imp, sfx)
		}
		return s
	}
	types := []string{"conn3x_windows_firewall_rule.win__rule", "conn3x_windows_scheduled_task.win__job"}
	if iis {
		types = append(types, "conn3x_windows_iis_app_pool.win__pool", "conn3x_windows_iis_site.win__site")
	} else {
		t.Log("no IIS on this runner: the pool and site aren't imported")
	}

	f.write(steps(false))
	f.expect(0, "init")
	t.Cleanup(func() { f.tool("destroy", "-auto-approve", "-no-color", "-input=false") })
	f.expect(0, "apply", "-auto-approve")
	if out, code := f.tool(append([]string{"state", "rm"}, types...)...); code != 0 {
		t.Fatalf("state rm: exit %d\n%s", code, out)
	}

	f.write(steps(true))
	out := f.expect(2, "plan", "-detailed-exitcode")
	if want := fmt.Sprintf("%d to import, 0 to add, 0 to change, 0 to destroy", len(types)); !strings.Contains(out, want) {
		t.Fatalf("plan after state rm: want %q\n%s", want, out)
	}
	f.expect(0, "apply", "-auto-approve")
	f.expect(0, "plan", "-detailed-exitcode")
}
