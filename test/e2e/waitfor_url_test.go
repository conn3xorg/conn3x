// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
	"time"
)

// wait_for's url asks from the host: the app listens only on the host's
// loopback, so the request can't come from here.
func TestWaitForURL(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "waitforurl")
	w.writeAs("main.circuit.hcl", circuitVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts})
	w.mustConn3x("init", "-no-color")
	start := time.Now()
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if took := time.Since(start); took < 3*time.Second {
		t.Fatalf("apply took %s, so it did not wait for the app", took)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}

	// Once the app stops, a refresh sees it, and the next apply waits again
	// and says what it got.
	h.exec("", "systemctl", "stop", "c3x-http.service")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "in_sync") {
		t.Fatalf("plan after the app stopped:\n%s", out)
	}
	out, code := w.conn3x("apply", "-auto-approve", "-no-color")
	if code == 0 || !strings.Contains(out, "timed out after 30s waiting for http://127.0.0.1:8080/healthz") {
		t.Fatalf("apply with the app down (exit %d):\n%s", code, out)
	}
}
