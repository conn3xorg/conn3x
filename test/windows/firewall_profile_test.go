// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build windowshost

package windowshost

import (
	"strings"
	"testing"
)

// The Public profile is turned on with inbound blocked and outbound allowed,
// drifted by hand and put back, and every plan and apply after it is a new
// login, so SSH still gets in. The runner's login is over loopback, which
// Windows Firewall doesn't filter, so the lockout check lets it through; the
// refusals are in the module's unit tests. The profile ends as it started,
// however the test ends.
func TestFirewallProfileFlow(t *testing.T) {
	f := newFlow(t)
	c := connect(t)
	read := func() string {
		return strings.TrimSpace(run(t, c, `$p = Get-NetFirewallProfile -Name Public; "$($p.Enabled)|$($p.DefaultInboundAction)|$($p.DefaultOutboundAction)"`, nil).Text)
	}
	orig := read()
	t.Cleanup(func() {
		parts := strings.Split(orig, "|")
		run(t, c, `param($A) Set-NetFirewallProfile -Name Public -Enabled $A.e -DefaultInboundAction $A.i -DefaultOutboundAction $A.o`,
			map[string]any{"e": parts[0], "i": parts[1], "o": parts[2]})
	})
	run(t, c, `Set-NetFirewallProfile -Name Public -Enabled False -DefaultInboundAction Allow`, nil)
	f.cycle(`step "public" {
    windows_firewall_profile {
      name             = "public"
      enabled          = true
      default_inbound  = "block"
      default_outbound = "allow"
    }
  }`, func() {
		run(t, c, `Set-NetFirewallProfile -Name Public -DefaultInboundAction Allow`, nil)
	})
	if got := read(); got != "True|Block|Allow" {
		t.Errorf("Public after the last apply: %s", got)
	}
}
