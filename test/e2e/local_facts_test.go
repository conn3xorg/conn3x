// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// TestHostLocalFacts reads a host's own facts, as JSON, as Ansible's INI
// .fact and from an executable one, into a step, and the next plan reads
// them the same.
func TestHostLocalFacts(t *testing.T) {
	for _, image := range []string{"rocky10", "debian13"} {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			h.exec("", "sh", "-c", `mkdir -p /etc/conn3x/facts.d /etc/ansible/facts.d
echo '{"row": "B", "unit": 12}' > /etc/conn3x/facts.d/rack.json
printf '[team]\nName = platform\n' > /etc/ansible/facts.d/owner.fact
printf '#!/bin/sh\necho "{\\"zone\\": \\"us-west\\"}"\n' > /etc/ansible/facts.d/dyn.fact
chmod +x /etc/ansible/facts.d/dyn.fact`)

			w := newWorkdir(t, "localfacts")
			w.write(circuitVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "cat", "/etc/conn3x-rack"); got != "B12 platform us-west\n" {
				t.Fatalf("rack file = %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			// A fact script that fails stops the plan and names the file.
			h.exec("", "sh", "-c", `printf '#!/bin/sh\necho nope >&2\nexit 3\n' > /etc/ansible/facts.d/dyn.fact`)
			if out, code := w.conn3x("plan", "-no-color"); code == 0 || !strings.Contains(out, "/etc/ansible/facts.d/dyn.fact: it exited with an error: nope") {
				t.Fatalf("plan with a failing fact script exited %d:\n%s", code, out)
			}
		})
	}
}
