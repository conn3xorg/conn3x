// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type whenVars struct {
	Ports           map[string]string
	Key, KnownHosts string
	RedHatWhen      string
}

// A step's when picks hosts by their facts at plan time: each host gets only
// its family's step, and a step without when still runs on both after
// them, under per_host. A when that turns false on a host removes the
// step's instance there, and with the default on_remove the host keeps what
// the step made.
func TestStepWhen(t *testing.T) {
	rh, deb := startHost(t, "rocky10"), startHost(t, "ubuntu2404")
	known := shareKey(t, rh, deb)

	w := newWorkdir(t, "when")
	vars := whenVars{
		Ports: map[string]string{"rh": rh.port, "deb": deb.port},
		Key:   rh.keyFile, KnownHosts: known,
		RedHatWhen: `local.family[each.key] == "redhat"`,
	}
	w.writeAs("main.tf", vars)
	w.mustConn3x("init", "-no-color")
	out := w.mustConn3x("apply", "-auto-approve", "-no-color")
	t.Logf("apply:\n%s", out)
	for h, want := range map[*host]string{rh: "redhat\n", deb: "debian\n"} {
		if got := h.exec("", "cat", "/etc/conn3x-when"); got != want {
			t.Errorf("/etc/conn3x-when = %q, want %q", got, want)
		}
		if got := h.exec("", "sh", "-c", "test -s /tmp/after && echo ran"); got != "ran\n" {
			t.Errorf("the step after the when steps didn't run: %q", got)
		}
	}
	if !strings.Contains(out, `conn3x_file.os__redhat["rh"]`) || strings.Contains(out, `conn3x_file.os__redhat["deb"]`) {
		t.Errorf("the redhat step should run on rh only:\n%s", out)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}

	// Turning when off on rh removes the step's instance there.
	vars.RedHatWhen = "false"
	w.writeAs("main.tf", vars)
	out = w.mustConn3x("plan", "-no-color")
	t.Logf("plan with when turned off:\n%s", out)
	if !strings.Contains(out, `conn3x_file.os__redhat["rh"] will be destroyed`) || !strings.Contains(out, "0 to add, 0 to change, 1 to destroy") {
		t.Fatalf("turning when off should remove the instance:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := rh.exec("", "cat", "/etc/conn3x-when"); got != "redhat\n" {
		t.Errorf("with on_remove = forget the file should stay, got %q", got)
	}
}
