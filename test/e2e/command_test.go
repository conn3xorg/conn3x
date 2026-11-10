// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type commandVars struct{ Port, KeyFile, KnownHosts string }

func TestCommandStep(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "command")
	w.writeAs("main.circuit.hcl", commandVars{h.port, h.keyFile, h.knownHosts})
	// In the environment: OpenTofu logs its command line, -var values too.
	w.env = append(w.env, "TF_VAR_token=T0ken-on-stdin")
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	// stdin_wo reached the command, and neither its command line nor state.
	if got := h.exec("", "cat", "/var/tmp/conn3x-token"); got != "T0ken-on-stdin" {
		t.Fatalf("the command read %q from stdin", got)
	}
	if line := h.exec("", "cat", "/var/tmp/conn3x-cmdline"); line == "" || strings.Contains(line, "T0ken") {
		t.Fatalf("the command line was %q", line)
	}
	if state, err := os.ReadFile(filepath.Join(w.dir, "terraform.tfstate")); err != nil || strings.Contains(string(state), "T0ken") || !strings.Contains(string(state), "stdin_hmac") {
		t.Fatalf("state holds the secret, or no stdin_hmac (%v)", err)
	}
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
