// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type editVars struct {
	Port, KeyFile, KnownHosts string
	WithLine                  bool
}

func TestLineAndBlock(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "edit")
			vars := editVars{h.port, h.keyFile, h.knownHosts, true}
			// A file the system owns; the circuit only edits parts of it.
			h.exec("# app\nport = 80\nname = demo\n", "sh", "-c", "cat > /etc/conn3x-app.conf")
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			want := "# app\nport = 8080\nname = demo\n# BEGIN CONN3X MANAGED BLOCK\nworkers = 4\ntimeout = 30\n# END CONN3X MANAGED BLOCK\n"
			if got := h.exec("", "cat", "/etc/conn3x-app.conf"); got != want {
				t.Fatalf("file = %q", got)
			}

			out := w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply is not empty:\n%s", out)
			}

			h.exec("", "sh", "-c", "sed -i 's/^workers = 4/workers = 99/' /etc/conn3x-app.conf")
			if out = w.mustConn3x("plan", "-no-color"); !strings.Contains(out, `conn3x_block.cfg__tuning["box"] will be updated in-place`) {
				t.Fatalf("block drift not planned:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			// Removing the line step with on_remove = "delete" takes the line out.
			vars.WithLine = false
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			want = "# app\nname = demo\n# BEGIN CONN3X MANAGED BLOCK\nworkers = 4\ntimeout = 30\n# END CONN3X MANAGED BLOCK\n"
			if got := h.exec("", "cat", "/etc/conn3x-app.conf"); got != want {
				t.Fatalf("after removing the line step: %q", got)
			}
		})
	}
}
