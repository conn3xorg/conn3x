// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type commandEnvVars struct{ Port, KeyFile, KnownHosts, Prefix string }

// A command step's environment reaches both command and unless, quoted so a
// value with a space or a ' arrives as written; a new value runs it again.
func TestCommandEnvironment(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "command-env")
	w.writeAs("main.circuit.hcl", commandEnvVars{h.port, h.keyFile, h.knownHosts, "/usr/local"})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", "/tmp/conn3x-env"); got != "/usr/local|it's a b" {
		t.Fatalf("the command saw %q", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("unless with the same environment should hold:\n%s", out)
	}
	w.writeAs("main.circuit.hcl", commandEnvVars{h.port, h.keyFile, h.knownHosts, "/opt/app"})
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", "/tmp/conn3x-env"); got != "/opt/app|it's a b" {
		t.Fatalf("after a new PREFIX the command saw %q", got)
	}
}
