// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build windowshost

package windowshost

import (
	"strings"
	"testing"
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
	if got := strings.TrimSpace(run(t, c, `(Get-TimeZone).Id`, nil).Text); got != want {
		t.Errorf("time zone after the last apply: %s", got)
	}

	f.write(`step "zone" {
    windows_timezone {
      name = "Tokyo Standrad Time"
    }
  }`)
	out := f.expect(1, "plan")
	if !strings.Contains(out, `Windows has no time zone "Tokyo Standrad Time"`) || !strings.Contains(out, `"Tokyo Standard Time"`) {
		t.Errorf("a misspelt zone:\n%s", out)
	}
}
