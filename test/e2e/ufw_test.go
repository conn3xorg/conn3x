// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type ufwVars struct{ Port, KeyFile, KnownHosts, DNSPort string }

// ufw keeps rules whether or not it is enabled, so this runs in containers;
// the droplet suite enables it on a real kernel.
func TestUFWRules(t *testing.T) {
	for _, image := range linuxImages {
		if image == "rocky10" {
			continue // ufw is a Debian-family tool; Rocky uses firewalld
		}
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "ufw")
			w.writeAs("main.circuit.hcl", ufwVars{h.port, h.keyFile, h.knownHosts, "53"})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			added := h.exec("", "ufw", "show", "added")
			for _, want := range []string{"ufw allow 22/tcp", "ufw deny from 10.0.0.0/8 to any port 6000:6007 proto tcp", "ufw allow from 192.0.2.1 to any port 53"} {
				if !strings.Contains(added, want+"\n") {
					t.Fatalf("ufw show added is missing %q:\n%s", want, added)
				}
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			w.writeAs("main.circuit.hcl", ufwVars{h.port, h.keyFile, h.knownHosts, "5353"})
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, `conn3x_ufw_rule.fw__dns["box"] must be replaced`) {
				t.Fatalf("port change not planned as a replacement:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			added = h.exec("", "ufw", "show", "added")
			if strings.Contains(added, "port 53\n") || !strings.Contains(added, "ufw allow from 192.0.2.1 to any port 5353\n") {
				t.Fatalf("old rule left behind or new one missing:\n%s", added)
			}
		})
	}
}
