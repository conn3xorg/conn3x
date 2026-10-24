// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type serviceVars struct{ Port, KeyFile, KnownHosts string }

func TestServiceLifecycle(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "service")
			w.writeAs("main.circuit.hcl", serviceVars{h.port, h.keyFile, h.knownHosts})
			w.mustConn3x("init", "-no-color")
			out := w.mustConn3x("apply", "-auto-approve", "-no-color")
			if !strings.Contains(out, "2 added") {
				t.Fatalf("apply:\n%s", out)
			}
			if got := strings.TrimSpace(h.exec("", "systemctl", "is-active", "conn3x-demo")); got != "active" {
				t.Fatalf("is-active = %s", got)
			}
			if got := strings.TrimSpace(h.exec("", "systemctl", "is-enabled", "conn3x-demo")); got != "enabled" {
				t.Fatalf("is-enabled = %s", got)
			}
			if out = w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply is not empty:\n%s", out)
			}

			h.exec("", "systemctl", "stop", "conn3x-demo")
			out = w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, `conn3x_service.app__run["box"] will be updated in-place`) {
				t.Fatalf("drift plan:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := strings.TrimSpace(h.exec("", "systemctl", "is-active", "conn3x-demo")); got != "active" {
				t.Fatalf("not restarted: is-active = %s", got)
			}
		})
	}
}
