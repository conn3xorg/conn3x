// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build windowshost

package windowshost

import (
	"strings"
	"testing"
)

// The runner is renamed without a reboot, which would end the job: the
// plan after it is clean with reboot_required true, a rename by hand to
// another name is drift, and asking for the running name back undoes the
// pending rename, which Rename-Computer itself refuses. The pending name
// is put back however the test ends.
func TestHostnameFlow(t *testing.T) {
	f := newFlow(t)
	c := connect(t)
	names := func() (running, pending string) {
		out := strings.TrimSpace(run(t, c, `$n = 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName'
"$((Get-ItemProperty -LiteralPath "$n\ActiveComputerName").ComputerName)|$((Get-ItemProperty -LiteralPath "$n\ComputerName").ComputerName)"`, nil).Text)
		running, pending, _ = strings.Cut(out, "|")
		return running, pending
	}
	orig, pending := names()
	if !strings.EqualFold(orig, pending) {
		t.Skipf("the runner already has a rename pending, %s to %s", orig, pending)
	}
	t.Cleanup(func() {
		run(t, c, `param($A)
Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Name ComputerName -Value $A.name
Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'NV Hostname' -Value $A.name`, map[string]any{"name": orig})
	})
	want := "C3X-" + strings.ToUpper(suffix())
	step := func(name string) string {
		return `step "name" {
    windows_hostname {
      name = "` + name + `"
    }
  }`
	}
	f.cycle(step(strings.ToLower(want)), func() {
		run(t, c, `Rename-Computer -NewName C3X-HAND -Force -WarningAction SilentlyContinue`, nil)
	})
	if running, pending := names(); running != orig || !strings.EqualFold(pending, want) {
		t.Errorf("after the last apply: running %s, pending %s", running, pending)
	}
	if got := rebootRequired(t, f); got != "true" {
		t.Errorf("reboot_required with a rename pending: %s", got)
	}

	f.write(step(orig))
	f.expect(0, "apply", "-auto-approve")
	f.expect(0, "plan", "-detailed-exitcode")
	if running, pending := names(); running != orig || !strings.EqualFold(pending, orig) {
		t.Errorf("after asking for the running name back: running %s, pending %s", running, pending)
	}
	if got := rebootRequired(t, f); got != "false" {
		t.Errorf("reboot_required with no rename pending: %s", got)
	}
}

// rebootRequired is the windows_hostname step's reboot_required in state,
// the only step the circuit has.
func rebootRequired(t *testing.T, f *flow) string {
	t.Helper()
	out, code := f.tool("show", "-json", "-no-color")
	switch {
	case code != 0:
		t.Fatalf("show: exit %d\n%s", code, out)
	case strings.Contains(out, `"reboot_required":true`):
		return "true"
	case strings.Contains(out, `"reboot_required":false`):
		return "false"
	}
	t.Fatalf("no reboot_required in state:\n%s", out)
	return ""
}
