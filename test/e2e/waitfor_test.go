// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
	"time"
)

func TestWaitFor(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "waitfor")
			w.writeAs("main.circuit.hcl", circuitVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts})
			w.mustConn3x("init", "-no-color")
			start := time.Now()
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if took := time.Since(start); took < 3*time.Second {
				t.Fatalf("apply took %s, so it did not wait for the file", took)
			}
			h.exec("", "test", "-e", "/run/conn3x-ready")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}
		})
	}
}
