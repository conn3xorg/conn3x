// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type commandVars struct{ Port, KeyFile, KnownHosts string }

func TestCommandStep(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "command")
	w.writeAs("main.circuit.hcl", commandVars{h.port, h.keyFile, h.knownHosts})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	runs := func() int { return strings.Count(h.exec("", "cat", "/var/tmp/conn3x-runs"), "\n") }
	if runs() != 1 {
		t.Fatalf("ran %d times", runs())
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply is not empty:\n%s", out)
	}
	h.exec("", "rm", "/var/tmp/conn3x-built")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "1 to change") {
		t.Fatalf("deleting the creates path did not plan a re-run:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if runs() != 2 {
		t.Fatalf("ran %d times after drift, want 2", runs())
	}
}
