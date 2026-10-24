// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type fsobjVars struct{ Port, KeyFile, KnownHosts, Release string }

func TestDirectoryAndLink(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "fsobj")
			w.writeAs("main.circuit.hcl", fsobjVars{h.port, h.keyFile, h.knownHosts, "v1"})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := strings.TrimSpace(h.exec("", "stat", "-c", "%a", "/opt/app/releases/v1")); got != "750" {
				t.Fatalf("mode = %s", got)
			}
			if got := strings.TrimSpace(h.exec("", "readlink", "/opt/app/current")); got != "releases/v1" {
				t.Fatalf("link -> %s", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			h.exec("", "chmod", "777", "/opt/app/releases/v1")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, `"0777" -> "0750"`) {
				t.Fatalf("mode drift not planned:\n%s", out)
			}

			w.writeAs("main.circuit.hcl", fsobjVars{h.port, h.keyFile, h.knownHosts, "v2"})
			out := w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, `conn3x_link.app__current["box"] will be updated in-place`) {
				t.Fatalf("retarget plan:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := strings.TrimSpace(h.exec("", "readlink", "/opt/app/current")); got != "releases/v2" {
				t.Fatalf("link -> %s after retarget", got)
			}
		})
	}
}
