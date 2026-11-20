// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build windowshost

package windowshost

import (
	"strings"
	"testing"
	"time"
)

// The runner's time zone is set to one it isn't in, drifted by hand and put
// back; it ends as it started however the test ends. A misspelt zone fails
// the plan with the closest real ones.
func TestTimezoneFlow(t *testing.T) {
	f := newFlow(t)
	c := connect(t)
	orig := strings.TrimSpace(run(t, c, `(Get-TimeZone).Id`, nil).Text)
	t.Cleanup(func() {
		run(t, c, `param($A) Set-TimeZone -Id $A.id`, map[string]any{"id": orig})
		// For a minute or more after a time zone change, each new SSH
		// session on the runner takes about 20 s to start, so the tests
		// after this one wait for that to pass rather than crawl through it.
		start := time.Now()
		for time.Since(start) < 4*time.Minute {
			call := time.Now()
			run(t, c, `1`, nil)
			if time.Since(call) < 5*time.Second {
				break
			}
			time.Sleep(20 * time.Second)
		}
		t.Logf("sessions were quick again %v after the time zone was put back", time.Since(start).Round(time.Second))
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

	f.write(`step "zone" {
    windows_timezone {
      name = "Tokyo Standrad Time"
    }
  }`)
	out := f.expect(1, "apply", "-auto-approve")
	if !strings.Contains(out, `Windows has no time zone "Tokyo Standrad Time"`) || !strings.Contains(out, `"Tokyo Standard Time"`) {
		t.Errorf("a misspelt zone:\n%s", out)
	}
}
