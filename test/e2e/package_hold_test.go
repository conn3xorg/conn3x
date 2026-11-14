// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type holdVars struct {
	Port, KeyFile, KnownHosts, State string
	Plugin                           bool
}

// package_hold holds a package with apt-mark or dnf versionlock, notices a
// release by hand, releases on request, and releases when the step goes.
func TestPackageHold(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			held := func() bool {
				cmd := "apt-mark showhold"
				if rpmImage(image) {
					cmd = "dnf -q versionlock list"
				}
				return strings.Contains(h.exec("", "sh", "-c", cmd+" 2>/dev/null; true"), "bash")
			}
			w := newWorkdir(t, "packagehold")
			// dnf 4 needs its plugin; dnf 5 has versionlock built in.
			dnf4 := image == "rocky10"
			vars := holdVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, State: "held"}
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")
			if dnf4 {
				if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code == 0 || !strings.Contains(out, "install python3-dnf-plugin-versionlock") {
					t.Fatalf("without the plugin (exit %d):\n%s", code, out)
				}
				vars.Plugin = true
				w.writeAs("main.circuit.hcl", vars)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if !held() {
				t.Fatal("bash isn't held after apply")
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			release := "apt-mark unhold bash"
			if rpmImage(image) {
				release = "dnf -q versionlock delete bash"
			}
			h.exec("", "sh", "-c", release)
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "1 to change") {
				t.Fatalf("plan after a release by hand:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if !held() {
				t.Fatal("apply didn't hold bash again")
			}

			vars.State = "released"
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if held() {
				t.Fatal(`bash is still held with state = "released"`)
			}
			vars.State = "held"
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			// on_remove = "delete" releases it when the step goes.
			w.mustConn3x("destroy", "-auto-approve", "-no-color")
			if held() {
				t.Fatal("bash is still held after destroy with on_remove = \"delete\"")
			}
		})
	}
}
