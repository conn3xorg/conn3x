// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build windowshost

package windowshost

import (
	"strings"
	"testing"
)

// TelnetClient needs no source and no reboot. It's turned on, drifted off by
// hand and put back, then turned off, and ends as it started however the
// test ends.
func TestOptionalFeatureFlow(t *testing.T) {
	f := newFlow(t)
	c := connect(t)
	state := func() string {
		return strings.TrimSpace(run(t, c, `[string](Get-WindowsOptionalFeature -Online -FeatureName TelnetClient).State`, nil).Text)
	}
	orig := state()
	if orig == "" {
		t.Skip("this runner has no TelnetClient feature")
	}
	t.Cleanup(func() {
		if orig == "Enabled" {
			run(t, c, `Enable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart | Out-Null`, nil)
		} else {
			run(t, c, `Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart | Out-Null`, nil)
		}
	})
	run(t, c, `Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart | Out-Null`, nil)
	f.cycle(`step "telnet" {
    windows_optional_feature {
      name = "TelnetClient"
    }
  }`, func() {
		run(t, c, `Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart | Out-Null`, nil)
	})
	if got := state(); got != "Enabled" {
		t.Errorf("TelnetClient after the last apply: %s", got)
	}
	f.write(`step "telnet" {
    windows_optional_feature {
      name  = "TelnetClient"
      state = "absent"
    }
  }`)
	f.expect(0, "apply", "-auto-approve")
	f.expect(0, "plan", "-detailed-exitcode")
	if got := state(); got != "Disabled" {
		t.Errorf("TelnetClient after state = absent: %s", got)
	}

	f.write(`step "nope" {
    windows_optional_feature {
      name = "Conn3xNoSuchFeature"
    }
  }`)
	if out := f.expect(1, "apply", "-auto-approve"); !strings.Contains(out, "Windows has no optional feature named Conn3xNoSuchFeature") {
		t.Errorf("an unknown feature:\n%s", out)
	}
}
