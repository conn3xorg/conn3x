// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
	"time"
)

func TestWaitFor(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "waitfor")
			w.writeAs("main.circuit.hcl", circuitVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts})
			w.mustConn3x("init", "-no-color")
			start := time.Now()
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if took := time.Since(start); took < 3*time.Second {
				t.Fatalf("apply took %s, so it did not wait for the file", took)
			}
			h.exec("", "test", "-e", "/run/conn3x-ready")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}
		})
	}
}

// contains waits for a line in the file, not just the file.
func TestWaitForContains(t *testing.T) {
	h := startHost(t, "debian13")
	w := newWorkdir(t, "waitfor-contains")
	w.writeAs("main.circuit.hcl", circuitVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts})
	w.mustConn3x("init", "-no-color")
	start := time.Now()
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if took := time.Since(start); took < 3*time.Second {
		t.Fatalf("apply took %s, so it did not wait for the line", took)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}
	h.exec("", "sh", "-c", "echo stopped > /run/conn3x-app.log")
	if out := w.mustConn3x("plan", "-no-color"); strings.Contains(out, "No changes.") {
		t.Fatalf("plan after the line went away shows no change:\n%s", out)
	}
}

// state "absent" waits for the path to be gone, and a port nothing listens
// on is already closed.
func TestWaitForAbsent(t *testing.T) {
	h := startHost(t, "debian13")
	w := newWorkdir(t, "waitfor-absent")
	w.writeAs("main.circuit.hcl", circuitVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts})
	w.mustConn3x("init", "-no-color")
	start := time.Now()
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if took := time.Since(start); took < 3*time.Second {
		t.Fatalf("apply took %s, so it did not wait for the lock to go", took)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}
	h.exec("", "touch", "/run/conn3x-lock")
	if out := w.mustConn3x("plan", "-no-color"); strings.Contains(out, "No changes.") {
		t.Fatalf("plan with the lock back shows no change:\n%s", out)
	}
}

type waitForTriggersVars struct{ Port, KeyFile, KnownHosts, N string }

// With triggers, wait_for waits again when they change, though the file
// was there when the plan read it: the step before took it away during
// the apply, as a restart takes a port away.
func TestWaitForTriggers(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "waitfor-triggers")
	apply := func(n string) time.Duration {
		w.writeAs("main.circuit.hcl", waitForTriggersVars{h.port, h.keyFile, h.knownHosts, n})
		start := time.Now()
		w.mustConn3x("apply", "-auto-approve", "-no-color")
		return time.Since(start)
	}
	w.writeAs("main.circuit.hcl", waitForTriggersVars{h.port, h.keyFile, h.knownHosts, "1"})
	w.mustConn3x("init", "-no-color")
	if took := apply("1"); took < 3*time.Second {
		t.Fatalf("first apply took %s, so it did not wait", took)
	}
	if took := apply("2"); took < 3*time.Second {
		t.Fatalf("apply with changed triggers took %s, so wait_for did not wait again", took)
	}
	h.exec("", "test", "-e", "/run/conn3x-ready")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}
}
