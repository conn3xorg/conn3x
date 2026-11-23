// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type serviceActionTryVars struct{ Port, KeyFile, KnownHosts, Memory string }

// try-restart restarts a running unit, try-reload leaves a stopped one
// stopped, and daemon-reload has systemd reread a drop-in without starting
// anything.
func TestServiceActionTryAndDaemonReload(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "service_action_try")
	show := func(prop, unit string) string {
		return strings.TrimSpace(h.exec("", "systemctl", "show", "-p", prop, "--value", unit))
	}

	w.writeAs("main.circuit.hcl", serviceActionTryVars{h.port, h.keyFile, h.knownHosts, "256M"})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	first := show("InvocationID", "conn3x-up")
	if first == "" || show("ActiveState", "conn3x-down") == "active" {
		t.Fatalf("after the first apply: conn3x-up invocation %q, conn3x-down %s", first, show("ActiveState", "conn3x-down"))
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}

	w.writeAs("main.circuit.hcl", serviceActionTryVars{h.port, h.keyFile, h.knownHosts, "512M"})
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := show("InvocationID", "conn3x-up"); got == first || got == "" {
		t.Fatalf("try-restart didn't restart the running unit (invocation %q -> %q)", first, got)
	}
	if got := show("ActiveState", "conn3x-down"); got == "active" {
		t.Fatal("try-reload started a stopped unit")
	}
	if got := show("NeedDaemonReload", "conn3x-down"); got != "no" {
		t.Fatalf("after daemon-reload, NeedDaemonReload = %q", got)
	}
	if got := show("MemoryMax", "conn3x-down"); got != "536870912" {
		t.Fatalf("systemd didn't reread the drop-in: MemoryMax = %q", got)
	}
}
