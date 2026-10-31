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

func TestDirectoryAbsent(t *testing.T) {
	h := startHost(t, "rocky10")
	h.exec("", "mkdir", "-p", "/var/cache/app-legacy")
	vars := fsobjVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts}
	w := newWorkdir(t, "directory_absent")
	w.write(vars)
	w.mustConn3x("init", "-no-color")

	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "sh", "-c", "test -e /var/cache/app-legacy && echo present || echo gone"); got != "gone\n" {
		t.Fatalf("/var/cache/app-legacy after apply: %s", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("second plan is not empty:\n%s", out)
	}

	// A directory that comes back with something in it is out of sync, but
	// apply leaves it and its contents in place.
	h.exec("", "sh", "-c", "mkdir /var/cache/app-legacy && echo keep > /var/cache/app-legacy/data")
	out := w.mustConn3x("plan", "-no-color")
	for _, want := range []string{`~ resource "conn3x_directory" "legacy"`, "1 to change"} {
		if !strings.Contains(out, want) {
			t.Fatalf("plan missing %q:\n%s", want, out)
		}
	}
	if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code == 0 || !strings.Contains(out, "is not empty, so it was left in place") {
		t.Fatalf("apply over a directory with files in it exited %d:\n%s", code, out)
	}
	if got := h.exec("", "cat", "/var/cache/app-legacy/data"); got != "keep\n" {
		t.Fatalf("contents after the refused apply: %q", got)
	}

	// Emptied, it is removed again.
	h.exec("", "rm", "/var/cache/app-legacy/data")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after removing it again is not empty:\n%s", out)
	}

	// Starting from empty state with the path already missing, apply
	// succeeds and the next plan is clean.
	w = newWorkdir(t, "directory_absent")
	w.write(vars)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan for a missing path is not empty:\n%s", out)
	}
}
