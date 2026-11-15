// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

type npmVars struct{ Port, KeyFile, KnownHosts, Semver, LeftPad string }

func startNodeHost(t *testing.T, image string) *host {
	t.Helper()
	h := startHost(t, image)
	install := "dnf -y -q install nodejs npm"
	if !rpmImage(image) {
		install = "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -q nodejs npm"
	}
	h.exec("", "sh", "-c", install)
	return h
}

// npmVersion is what npm ls reports at the top of the tree, global or in dir.
func npmVersion(h *host, dir, name string) string {
	args := []string{"exec", h.container, "sh", "-c"}
	if dir == "" {
		args = append(args, "npm ls -g --json --depth=0 "+name+" || true")
	} else {
		args = append(args, "cd "+dir+" && npm ls --json --depth=0 "+name+" || true")
	}
	out, _ := exec.Command("podman", args...).Output()
	var tree struct {
		Dependencies map[string]struct{ Version string }
	}
	_ = json.Unmarshal(out, &tree)
	return tree.Dependencies[name].Version
}

func TestNpm(t *testing.T) {
	for _, image := range []string{"rocky10", "debian13"} {
		t.Run(image, func(t *testing.T) {
			h := startNodeHost(t, image)
			h.exec("", "mkdir", "-p", "/opt/app")
			w := newWorkdir(t, "npm")
			w.writeAs("main.circuit.hcl", npmVars{h.port, h.keyFile, h.knownHosts, "7.6.3", "1.3.0"})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			if got := npmVersion(h, "", "semver"); got != "7.6.3" {
				t.Fatalf("semver = %q", got)
			}
			if got := npmVersion(h, "/opt/app", "left-pad"); got != "1.3.0" {
				t.Fatalf("left-pad = %q", got)
			}
			if got := npmVersion(h, "/opt/app", "is-number"); got == "" {
				t.Fatal("is-number missing")
			}

			// Pinned and latest both settle.
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply is not empty:\n%s", out)
			}

			// Someone moves a pin by hand.
			h.exec("", "sh", "-c", "cd /opt/app && npm install --no-fund --no-audit --loglevel=error left-pad@1.2.0")
			out, code := w.conn3x("drift", "-no-color")
			if code != 2 || !strings.Contains(out, `conn3x_npm.node__dep["box"]`) {
				t.Fatalf("drift exited %d:\n%s", code, out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := npmVersion(h, "/opt/app", "left-pad"); got != "1.3.0" {
				t.Fatalf("left-pad after repair = %q", got)
			}

			// Changing the pins goes up globally and down in the project.
			w.writeAs("main.circuit.hcl", npmVars{h.port, h.keyFile, h.knownHosts, "7.7.1", "1.2.0"})
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := npmVersion(h, "", "semver"); got != "7.7.1" {
				t.Fatalf("semver after a higher pin = %q", got)
			}
			if got := npmVersion(h, "/opt/app", "left-pad"); got != "1.2.0" {
				t.Fatalf("left-pad after a lower pin = %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after changing pins is not empty:\n%s", out)
			}

			// state = "absent" takes both out, and settles.
			w.writeAs("main.circuit.hcl", npmVars{h.port, h.keyFile, h.knownHosts, "", ""})
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := npmVersion(h, "", "semver"); got != "" {
				t.Fatalf("semver after removal = %q", got)
			}
			if got := npmVersion(h, "/opt/app", "left-pad"); got != "" {
				t.Fatalf("left-pad after removal = %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after removal is not empty:\n%s", out)
			}
		})
	}
}
