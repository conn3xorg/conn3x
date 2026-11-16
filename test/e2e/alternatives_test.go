// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type alternativesVars struct {
	Port, KeyFile, KnownHosts, Path string
}

// TestAlternatives registers a path for a name another path already holds,
// selects it, switches to the other, and removes it, on both tool families.
func TestAlternatives(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			h.exec("", "sh", "-c", "printf '#!/bin/sh\\n' > /usr/local/bin/a && cp /usr/local/bin/a /usr/local/bin/b && chmod +x /usr/local/bin/a /usr/local/bin/b")
			tool := "update-alternatives"
			if rpmImage(image) {
				tool = "alternatives"
			}
			// b is registered first and wins auto mode, so selecting a
			// takes both an --install and a --set.
			h.exec("", tool, "--install", "/usr/local/bin/tool", "tool", "/usr/local/bin/b", "20")

			w := newWorkdir(t, "alternatives")
			w.writeAs("main.circuit.hcl", alternativesVars{h.port, h.keyFile, h.knownHosts, "/usr/local/bin/a"})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := strings.TrimSpace(h.exec("", "readlink", "/etc/alternatives/tool")); got != "/usr/local/bin/a" {
				t.Fatalf("tool points to %q after apply", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			w.writeAs("main.circuit.hcl", alternativesVars{h.port, h.keyFile, h.knownHosts, "/usr/local/bin/b"})
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := strings.TrimSpace(h.exec("", "readlink", "/etc/alternatives/tool")); got != "/usr/local/bin/b" {
				t.Fatalf("tool points to %q after the change", got)
			}
			if out := h.exec("", tool, "--display", "tool"); !strings.Contains(out, "/usr/local/bin/b - priority 10") {
				t.Fatalf("b wasn't re-registered at priority 10:\n%s", out)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after the change:\n%s", out)
			}

			w.writeAs("main.circuit.hcl", alternativesVars{h.port, h.keyFile, h.knownHosts, ""})
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if out := h.exec("", tool, "--display", "tool"); strings.Contains(out, "/usr/local/bin/b") || !strings.Contains(out, "points to /usr/local/bin/a") {
				t.Fatalf("after removal:\n%s", out)
			}
		})
	}
}

// TestAlternativesKeepsTheChoice: a name already pointing at the path in
// auto mode isn't in sync until it's set by hand, so a package that later
// registers a higher priority doesn't take it over.
func TestAlternativesKeepsTheChoice(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			h.exec("", "sh", "-c", "printf '#!/bin/sh\\n' > /usr/local/bin/a && cp /usr/local/bin/a /usr/local/bin/c && chmod +x /usr/local/bin/a /usr/local/bin/c")
			tool := "update-alternatives"
			if rpmImage(image) {
				tool = "alternatives"
			}
			// a is the only choice, at the step's own priority, so auto
			// mode already points at it: nothing to register or switch.
			h.exec("", tool, "--install", "/usr/local/bin/tool", "tool", "/usr/local/bin/a", "10")

			w := newWorkdir(t, "alternatives")
			w.writeAs("main.circuit.hcl", alternativesVars{h.port, h.keyFile, h.knownHosts, "/usr/local/bin/a"})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if out := h.exec("", tool, "--display", "tool"); !strings.Contains(out, "manual") {
				t.Fatalf("not in manual mode after apply:\n%s", out)
			}

			// A package registers a higher priority, as a newer JDK would.
			h.exec("", tool, "--install", "/usr/local/bin/tool", "tool", "/usr/local/bin/c", "100")
			if got := strings.TrimSpace(h.exec("", "readlink", "/etc/alternatives/tool")); got != "/usr/local/bin/a" {
				t.Fatalf("a higher priority took tool over: it points to %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after the higher priority:\n%s", out)
			}
		})
	}
}
