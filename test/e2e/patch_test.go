// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type patchVars struct{ Port, KeyFile, KnownHosts, State string }

// patch applies a patch and plans clean, shows a file reverted by hand as
// drift and patches it again, refuses a file that has moved on, takes the
// patch out with state = "absent", and takes it out again when the step
// goes with on_remove = "delete".
func TestPatch(t *testing.T) {
	for _, image := range []string{"rocky10", "debian13"} {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			conf := func() string { return h.exec("", "cat", "/etc/demo.conf") }
			const orig, patched = "a\nb\nc\n", "a\nB\nc\n"
			w := newWorkdir(t, "patch")
			vars := patchVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, State: "present"}
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := conf(); got != patched {
				t.Fatalf("after apply: %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			h.exec(orig, "sh", "-c", "cat > /etc/demo.conf")
			out := w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, "1 to change") || !strings.Contains(out, `"not_applied"`) {
				t.Fatalf("plan after reverting by hand:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := conf(); got != patched {
				t.Fatalf("apply didn't patch it again: %q", got)
			}

			// A file that has moved on fails the apply and stays as it is.
			h.exec("x\ny\nz\n", "sh", "-c", "cat > /etc/demo.conf")
			out, code := w.conn3x("apply", "-auto-approve", "-no-color")
			if code == 0 || !strings.Contains(out, "has moved on") || !strings.Contains(out, "FAILED") {
				t.Fatalf("apply on a changed file: exit %d\n%s", code, out)
			}
			if got := conf(); got != "x\ny\nz\n" {
				t.Fatalf("a failed apply changed the file: %q", got)
			}
			h.exec(patched, "sh", "-c", "cat > /etc/demo.conf")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan with the patch back by hand:\n%s", out)
			}

			vars.State = "absent"
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := conf(); got != orig {
				t.Fatalf("state absent: %q", got)
			}

			vars.State = "present"
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			vars.State = ""
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := conf(); got != orig {
				t.Fatalf("after the step went with on_remove = delete: %q", got)
			}
			if ls := h.exec("", "ls", "/etc"); strings.Contains(ls, "demo.conf.orig") || strings.Contains(ls, "demo.conf.rej") {
				t.Fatalf("backup or reject left beside the file:\n%s", ls)
			}
		})
	}
}
