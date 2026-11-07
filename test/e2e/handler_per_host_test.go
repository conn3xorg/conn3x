// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type chainHandlerVars struct {
	Ports                       map[string]string
	Key, KnownHosts, Slow, Fail string
}

// starts reads the timestamps the demo service writes each time it starts.
func starts(t *testing.T, h *host) []float64 {
	t.Helper()
	var out []float64
	for _, line := range strings.Fields(h.exec("", "sh", "-c", "cat /tmp/starts 2>/dev/null || true")) {
		out = append(out, stamp(t, line))
	}
	return out
}

// Under per_host a host's handler runs once that host's steps finish: a and
// b restart their service while slow is still on its last step.
func TestHandlerPerHost(t *testing.T) {
	a, b, slow := startHost(t, "rocky10"), startHost(t, "rocky10"), startHost(t, "rocky10")
	knownFile := shareKey(t, a, b, slow)

	w := newWorkdir(t, "chain_handler")
	w.writeAs("main.circuit.hcl", chainHandlerVars{
		Ports: map[string]string{"a": a.port, "b": b.port, "slow": slow.port},
		Key:   a.keyFile, KnownHosts: knownFile, Slow: "slow",
	})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")

	slowLast := stamp(t, slow.exec("", "cat", "/tmp/last"))
	for name, h := range map[string]*host{"a": a, "b": b, "slow": slow} {
		// One start from the run step, one from the handler.
		if s := starts(t, h); len(s) != 2 {
			t.Fatalf("%s started the service %d times, want 2 (run step, then handler)", name, len(s))
		}
	}
	if restart := starts(t, slow)[1]; restart < slowLast {
		t.Errorf("slow's handler ran before its last step finished: %.3f < %.3f", restart, slowLast)
	}
	for name, h := range map[string]*host{"a": a, "b": b} {
		restart := starts(t, h)[1]
		t.Logf("%s's handler ran %.1fs before slow finished its last step", name, slowLast-restart)
		if restart >= slowLast {
			t.Errorf("%s's handler waited for slow: restart at %.3f, slow's last step at %.3f", name, restart, slowLast)
		}
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}
}

// A step that fails on one host skips the handler there and nowhere else.
func TestHandlerPerHostSkipsFailedHost(t *testing.T) {
	a, b := startHost(t, "rocky10"), startHost(t, "rocky10")
	knownFile := shareKey(t, a, b)

	w := newWorkdir(t, "chain_handler")
	w.writeAs("main.circuit.hcl", chainHandlerVars{
		Ports: map[string]string{"a": a.port, "b": b.port},
		Key:   a.keyFile, KnownHosts: knownFile, Fail: "b",
	})
	w.mustConn3x("init", "-no-color")
	if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code == 0 {
		t.Fatalf("apply passed although the last step failed on b:\n%s", out)
	}
	if n := len(starts(t, a)); n != 2 {
		t.Errorf("a started the service %d times, want 2: its handler should still run", n)
	}
	if n := len(starts(t, b)); n != 1 {
		t.Errorf("b started the service %d times, want 1: its handler should be skipped", n)
	}
}
