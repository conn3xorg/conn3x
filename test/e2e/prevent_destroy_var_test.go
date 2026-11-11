// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// A step's prevent_destroy can come from a variable, which OpenTofu
// resources long couldn't: protected, a destroy is refused and the file
// stays; with the variable false, the same destroy goes ahead.
func TestStepPreventDestroyFromAVariable(t *testing.T) {
	h := startHost(t, "ubuntu2404")
	w := newWorkdir(t, "prevent_destroy_var")
	w.writeAs("main.circuit.hcl", struct{ Port, KeyFile, KnownHosts string }{h.port, h.keyFile, h.knownHosts})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color", "-var", "protect=true")

	out, code := w.conn3x("destroy", "-auto-approve", "-no-color", "-var", "protect=true")
	if code == 0 || !strings.Contains(out, "prevent_destroy") {
		t.Fatalf("a protected destroy exited %d:\n%s", code, out)
	}
	if got := h.exec("", "cat", "/etc/motd"); got != "kept\n" {
		t.Fatalf("/etc/motd after the refused destroy: %q", got)
	}
	w.mustConn3x("destroy", "-auto-approve", "-no-color", "-var", "protect=false")
}
