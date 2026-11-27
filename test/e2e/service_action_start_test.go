// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type serviceActionStartVars struct{ Port, KeyFile, KnownHosts, N, Exit string }

// start runs a oneshot unit when the step is created and again when its
// triggers change, and a oneshot that fails fails the apply.
func TestServiceActionStartOneshot(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "service_action_start")
	runs := func() int {
		return strings.Count(h.exec("", "sh", "-c", "cat /root/once.log 2>/dev/null || true"), "run")
	}
	apply := func(n, exit string) (string, int) {
		w.writeAs("main.circuit.hcl", serviceActionStartVars{h.port, h.keyFile, h.knownHosts, n, exit})
		return w.conn3x("apply", "-auto-approve", "-no-color")
	}

	w.writeAs("main.circuit.hcl", serviceActionStartVars{h.port, h.keyFile, h.knownHosts, "1", "0"})
	w.mustConn3x("init", "-no-color")
	if out, code := apply("1", "0"); code != 0 || runs() != 1 {
		t.Fatalf("first apply: exit %d, %d runs:\n%s", code, runs(), out)
	}
	if out, code := apply("1", "0"); code != 0 || runs() != 1 {
		t.Fatalf("unchanged apply: exit %d, %d runs, want 1:\n%s", code, runs(), out)
	}
	if out, code := apply("2", "0"); code != 0 || runs() != 2 {
		t.Fatalf("changed triggers: exit %d, %d runs, want 2:\n%s", code, runs(), out)
	}
	out, code := apply("3", "1")
	if code == 0 || !strings.Contains(out, "conn3x-once.service") {
		t.Fatalf("a failing oneshot: exit %d, want an error naming the unit:\n%s", code, out)
	}
	if runs() != 3 {
		t.Fatalf("failing oneshot ran %d times in all, want 3", runs())
	}
}
