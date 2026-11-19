// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// On a host without SELinux, as every test container is, a selinux_port
// step applies, needs no semanage, and the second plan is empty. The
// droplet test covers a host with SELinux.
func TestSELinuxPortWithoutSELinux(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "selinux-port")
			w.writeAs("main.circuit.hcl", serviceVars{h.port, h.keyFile, h.knownHosts})
			w.mustConn3x("init", "-no-color")
			if out := w.mustConn3x("apply", "-auto-approve", "-no-color"); !strings.Contains(out, "1 added") {
				t.Fatalf("apply:\n%s", out)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply is not empty:\n%s", out)
			}
		})
	}
}
