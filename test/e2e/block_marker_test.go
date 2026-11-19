// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type blockMarkerVars struct{ Port, KeyFile, KnownHosts, Marker string }

// Changing a block step's marker moves the block to the new markers, so
// the file holds one block, not the old one beside a new one.
func TestBlockMarkerChange(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "block-marker")
	w.writeAs("main.circuit.hcl", blockMarkerVars{h.port, h.keyFile, h.knownHosts, "# {mark} app"})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")

	w.writeAs("main.circuit.hcl", blockMarkerVars{h.port, h.keyFile, h.knownHosts, "; {mark} app"})
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	got := h.exec("", "cat", "/etc/conn3x-block.conf")
	if want := "; BEGIN app\nkey = value\n; END app\n"; got != want {
		t.Fatalf("after the marker change the file is %q, want %q", got, want)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after the change is not empty:\n%s", out)
	}
}
