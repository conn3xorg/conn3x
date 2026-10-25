// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

func TestDrift(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "drift")
	w.writeAs("main.circuit.hcl", circuitVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")

	if out, code := w.conn3x("drift", "-no-color"); code != 0 || !strings.Contains(out, "No drift") {
		t.Fatalf("drift right after apply exited %d:\n%s", code, out)
	}

	h.exec("", "sh", "-c", "echo 'edited by hand' > /etc/motd")
	out, code := w.conn3x("drift", "-no-color")
	if code != 2 {
		t.Fatalf("drift after a hand edit exited %d, want 2:\n%s", code, out)
	}
	for _, want := range []string{"Drift found in 1 resource.", "Hosts", `~ conn3x_file.drift__motd["box"]  changed`} {
		if !strings.Contains(out, want) {
			t.Fatalf("drift output is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Cloud") {
		t.Fatalf("a host edit was reported as cloud drift:\n%s", out)
	}
	// drift changes nothing: the hand edit is still there.
	if got := h.exec("", "cat", "/etc/motd"); got != "edited by hand\n" {
		t.Fatalf("drift changed the host: %q", got)
	}
}
