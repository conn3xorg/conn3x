// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type capsVars struct{ Port, KeyFile, KnownHosts, Pkg, Caps string }

// file_capabilities sets a file's capabilities, puts them back after they
// go by hand, takes off one no longer listed, and takes them all off when
// the step goes with on_remove = "delete".
func TestFileCapabilities(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			getcap := func() string { return h.exec("", "sh", "-c", "getcap /usr/local/bin/capdemo; true") }
			pkg := "libcap2-bin"
			if rpmImage(image) {
				pkg = "libcap"
			}
			w := newWorkdir(t, "file_capabilities")
			vars := capsVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Pkg: pkg, Caps: `"cap_net_raw+ep", "cap_net_bind_service+ep"`}
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := getcap(); !strings.Contains(got, "cap_net_bind_service,cap_net_raw") {
				t.Fatalf("after apply: %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			h.exec("", "setcap", "-r", "/usr/local/bin/capdemo")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "1 to change") {
				t.Fatalf("plan after setcap -r by hand:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := getcap(); !strings.Contains(got, "cap_net_raw") {
				t.Fatalf("apply didn't put them back: %q", got)
			}

			vars.Caps = `"cap_net_raw=ep"`
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := getcap(); !strings.Contains(got, "cap_net_raw") || strings.Contains(got, "cap_net_bind_service") {
				t.Fatalf("with one left: %q", got)
			}

			vars.Caps = ""
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := strings.TrimSpace(getcap()); got != "" {
				t.Fatalf("after the step went: %q", got)
			}
		})
	}
}
