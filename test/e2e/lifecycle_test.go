// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type lifecycleVars struct {
	Port, KeyFile, KnownHosts string
	Allowed                   string
	NoHosts, Wheel            bool
}

// A step's lifecycle block: ignore_changes leaves a hand edit alone, also
// when another argument of the same step changes; prevent_destroy stops a
// host's removal; a precondition stops the plan with its message.
func TestStepLifecycle(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "lifecycle")
	vars := lifecycleVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Allowed: "box"}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")

	h.exec("hand edit\n", "sh", "-c", "cat > /etc/motd")
	h.exec("", "usermod", "-s", "/bin/bash", "alice")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("ignored hand edits show in the plan:\n%s", out)
	}

	// Changing groups updates alice; the ignored shell must survive it.
	vars.Wheel = true
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := strings.TrimSpace(h.exec("", "getent", "passwd", "alice")); !strings.HasSuffix(got, ":/bin/bash") {
		t.Fatalf("apply reset the ignored shell: %q", got)
	}
	if got := h.exec("", "cat", "/etc/motd"); got != "hand edit\n" {
		t.Fatalf("/etc/motd = %q, want the hand edit", got)
	}

	vars.NoHosts = true
	w.writeAs("main.circuit.hcl", vars)
	out, code := w.conn3x("plan", "-no-color")
	if code == 0 || !strings.Contains(out, "Resource instance cannot be destroyed") || !strings.Contains(out, `conn3x_file.life__motd["box"]`) {
		t.Fatalf("prevent_destroy did not stop the removal (exit %d):\n%s", code, out)
	}

	vars.NoHosts, vars.Allowed = false, "web1"
	w.writeAs("main.circuit.hcl", vars)
	out, code = w.conn3x("plan", "-no-color")
	if code == 0 || !strings.Contains(out, "Only web1 runs this circuit, not box.") {
		t.Fatalf("precondition did not fail the plan (exit %d):\n%s", code, out)
	}
}
