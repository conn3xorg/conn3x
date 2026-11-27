// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type serviceActionStartVars struct{ Port, KeyFile, KnownHosts, Remain, N, Exit string }

// start runs a oneshot unit when the step is created and again when its
// triggers change, and a oneshot that fails fails the apply. With
// RemainAfterExit=yes the unit stays active after a run, and it still has
// to run again.
func TestServiceActionStartOneshot(t *testing.T) {
	for _, remain := range []string{"no", "yes"} {
		t.Run("RemainAfterExit="+remain, func(t *testing.T) {
			h := startHost(t, "rocky10")
			w := newWorkdir(t, "service_action_start")
			runs := func() int {
				return strings.Count(h.exec("", "sh", "-c", "cat /root/once.log 2>/dev/null || true"), "run")
			}
			apply := func(n, exit string) (string, int) {
				w.writeAs("main.circuit.hcl", serviceActionStartVars{h.port, h.keyFile, h.knownHosts, remain, n, exit})
				return w.conn3x("apply", "-auto-approve", "-no-color")
			}

			w.writeAs("main.circuit.hcl", serviceActionStartVars{h.port, h.keyFile, h.knownHosts, remain, "1", "0"})
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
		})
	}
}

type serviceActionResetVars struct{ Port, KeyFile, KnownHosts, N, Reset string }

// A unit with StartLimitBurst=1 refuses a second restart within the hour;
// reset_failed clears the limit so the restart goes through.
func TestServiceActionResetFailed(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "service_action_reset_failed")
	apply := func(n, reset string) (string, int) {
		w.writeAs("main.circuit.hcl", serviceActionResetVars{h.port, h.keyFile, h.knownHosts, n, reset})
		return w.conn3x("apply", "-auto-approve", "-no-color")
	}

	w.writeAs("main.circuit.hcl", serviceActionResetVars{h.port, h.keyFile, h.knownHosts, "1", "false"})
	w.mustConn3x("init", "-no-color")
	if out, code := apply("1", "false"); code != 0 {
		t.Fatalf("first apply exited %d:\n%s", code, out)
	}
	if out, code := apply("2", "false"); code == 0 {
		t.Fatalf("a second restart inside the start limit succeeded, so the test proves nothing:\n%s", out)
	}
	if out, code := apply("3", "true"); code != 0 {
		t.Fatalf("restart with reset_failed exited %d:\n%s", code, out)
	}
	if got := strings.TrimSpace(h.exec("", "systemctl", "is-active", "conn3x-limited")); got != "active" {
		t.Fatalf("conn3x-limited is %q after the reset_failed restart", got)
	}
}
