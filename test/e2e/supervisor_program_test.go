// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type supervisorVars struct {
	Port, KeyFile, KnownHosts, Seconds string
	Program                            bool
}

// supervisor_program loads and starts a program supervisord didn't know,
// plans clean, shows a program stopped by hand as drift and starts it
// again, restarts it when its file changes, and stops and removes it when
// the step goes with on_remove = "delete".
func TestSupervisorProgram(t *testing.T) {
	h := startHost(t, "ubuntu2404")
	status := func() string {
		return h.exec("", "sh", "-c", "supervisorctl status demo; true")
	}
	pid := func() string { return strings.TrimSpace(h.exec("", "sh", "-c", "supervisorctl pid demo")) }
	w := newWorkdir(t, "supervisor_program")
	vars := supervisorVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Seconds: "86400", Program: true}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	// autostart=false, so it's running only because the step started it.
	if got := status(); !strings.Contains(got, "RUNNING") {
		t.Fatalf("after apply: %q", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}

	h.exec("", "supervisorctl", "stop", "demo")
	out := w.mustConn3x("plan", "-no-color")
	if !strings.Contains(out, "1 to change") || !strings.Contains(out, `"STOPPED"`) {
		t.Fatalf("plan after supervisorctl stop by hand:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := status(); !strings.Contains(got, "RUNNING") {
		t.Fatalf("apply didn't start it again: %q", got)
	}

	before := pid()
	vars.Seconds = "86401"
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := status(); !strings.Contains(got, "RUNNING") || pid() == before {
		t.Fatalf("a changed file didn't restart it: %q, pid %s was %s", got, pid(), before)
	}

	vars.Program = false
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := status(); !strings.Contains(got, "no such process") {
		t.Fatalf("after the step went: %q", got)
	}
}
