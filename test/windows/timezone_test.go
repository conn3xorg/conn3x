// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build windowshost

package windowshost

import (
	"os"
	"strings"
	"testing"
)

// The runner's own zone, set again in another case, plans clean and changes
// nothing, and a misspelt zone fails with the closest real ones. Neither
// changes the runner's time zone (see TestTimezoneFlow for why).
func TestTimezoneReadOnly(t *testing.T) {
	f := newFlow(t)
	c := connect(t)
	orig := strings.TrimSpace(run(t, c, `(Get-TimeZone).Id`, nil).Text)
	f.write(`step "zone" {
    windows_timezone {
      name = "` + strings.ToLower(orig) + `"
    }
  }`)
	f.expect(0, "init")
	f.expect(0, "apply", "-auto-approve")
	f.expect(0, "plan", "-detailed-exitcode")
	if got := strings.TrimSpace(run(t, c, `(Get-TimeZone).Id`, nil).Text); got != orig {
		t.Fatalf("the runner's zone changed from %s to %s", orig, got)
	}

	f.write(`step "zone" {
    windows_timezone {
      name = "Tokyo Standrad Time"
    }
  }`)
	out := f.expect(1, "apply", "-auto-approve")
	if !strings.Contains(out, `Windows has no time zone "Tokyo Standrad Time"`) || !strings.Contains(out, `"Tokyo Standard Time"`) {
		t.Errorf("a misspelt zone:\n%s", out)
	}
	if got := strings.TrimSpace(run(t, c, `(Get-TimeZone).Id`, nil).Text); got != orig {
		t.Fatalf("the runner's zone changed from %s to %s", orig, got)
	}
}

// The runner's time zone is set to one it isn't in, drifted by hand and put
// back. Only with CONN3X_WIN_TZ_CHANGE set: on GitHub's Windows runners, each
// new SSH session took about 20 s to start after a time zone change, and
// stayed that slow for the rest of the job, even after the zone was put back
// and nine minutes without a session, which ran the suite past its time limit.
func TestTimezoneFlow(t *testing.T) {
	if os.Getenv("CONN3X_WIN_TZ_CHANGE") == "" {
		t.Skip("set CONN3X_WIN_TZ_CHANGE to change the host's time zone: it slows new SSH sessions on GitHub's runners for the rest of the job")
	}
	f := newFlow(t)
	c := connect(t)
	orig := strings.TrimSpace(run(t, c, `(Get-TimeZone).Id`, nil).Text)
	t.Cleanup(func() {
		run(t, c, `param($A) Set-TimeZone -Id $A.id`, map[string]any{"id": orig})
	})
	want, other := "Tokyo Standard Time", "Cape Verde Standard Time"
	if strings.EqualFold(orig, want) {
		want, other = other, want
	}
	f.cycle(`step "zone" {
    windows_timezone {
      name = "`+strings.ToLower(want)+`"
    }
  }`, func() {
		run(t, c, `param($A) Set-TimeZone -Id $A.id`, map[string]any{"id": other})
	})
	// Windows keeps the ID in the case it was set with.
	if got := strings.TrimSpace(run(t, c, `(Get-TimeZone).Id`, nil).Text); !strings.EqualFold(got, want) {
		t.Errorf("time zone after the last apply: %s", got)
	}
}
