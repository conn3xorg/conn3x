// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type handlerVars struct{ Port, KeyFile, KnownHosts, Greeting string }

func TestHandlerRunsOnlyOnChange(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "handler")
	invocation := func() string {
		return strings.TrimSpace(h.exec("", "systemctl", "show", "-p", "InvocationID", "--value", "conn3x-demo"))
	}

	w.writeAs("main.circuit.hcl", handlerVars{h.port, h.keyFile, h.knownHosts, "hello"})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	first := invocation()
	if first == "" {
		t.Fatal("service is not running after the first apply")
	}

	// Nothing changed: no restart.
	if out := w.mustConn3x("apply", "-auto-approve", "-no-color"); !strings.Contains(out, "0 added, 0 changed, 0 destroyed") {
		t.Fatalf("second apply changed something:\n%s", out)
	}
	if got := invocation(); got != first {
		t.Fatal("the handler restarted the service although nothing changed")
	}

	// The notifying step changes: the handler restarts the service.
	w.writeAs("main.circuit.hcl", handlerVars{h.port, h.keyFile, h.knownHosts, "goodbye"})
	out := w.mustConn3x("plan", "-no-color")
	if !strings.Contains(out, `conn3x_service_action.app__restart["box"] must be replaced`) {
		t.Fatalf("plan does not show the handler running:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := invocation(); got == first || got == "" {
		t.Fatalf("service was not restarted (invocation %q -> %q)", first, got)
	}
}
