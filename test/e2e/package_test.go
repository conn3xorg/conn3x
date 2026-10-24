// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os/exec"
	"strings"
	"testing"
)

type packageVars struct {
	Port, KeyFile, KnownHosts string
	WithPackage               bool
}

func TestPackageLifecycle(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "package")
			vars := packageVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, WithPackage: true}
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")

			out := w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, `conn3x_package.tools__tree["box"] will be created`) {
				t.Fatalf("plan:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			h.exec("", "sh", "-c", "command -v tree")

			if out = w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after install is not empty:\n%s", out)
			}

			// Removing it by hand shows up as drift and apply reinstalls it.
			remove := "dnf -y -q remove tree"
			if image != "rocky10" { // apt-based images
				remove = "DEBIAN_FRONTEND=noninteractive apt-get -y -q remove tree"
			}
			h.exec("", "sh", "-c", remove)
			out = w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, "1 to change") || !strings.Contains(out, "installed_version") {
				t.Fatalf("drift plan:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			h.exec("", "sh", "-c", "command -v tree")

			// on_remove = "delete" uninstalls it when the step goes away.
			vars.WithPackage = false
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if err := exec.Command("podman", "exec", h.container, "sh", "-c", "command -v tree").Run(); err == nil {
				t.Fatal("tree still installed after removing the step with on_remove = delete")
			}
		})
	}
}
