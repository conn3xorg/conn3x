// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type importHostVars struct {
	Port, KeyFile, KnownHosts string
	Hostname, Zone            string
}

// A host set up by hand always has a hostname, time zone and locale, so
// import adopts them with nothing to change, the next plan is empty, and a
// different time zone plans just that change. The hostname is the one
// podman gave the container: hostnamectl can't set one inside it.
func TestStepImportHostSettings(t *testing.T) {
	h := startHost(t, "rocky10")
	h.exec("", "ln", "-sf", "../usr/share/zoneinfo/Europe/Dublin", "/etc/localtime")
	h.exec("LANG=C.UTF-8\n", "sh", "-c", "cat > /etc/locale.conf")
	name := strings.TrimSpace(h.exec("", "uname", "-n"))
	h.exec(name+"\n", "sh", "-c", "cat > /etc/hostname")

	w := newWorkdir(t, "import_host")
	vars := importHostVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Hostname: name, Zone: "Europe/Dublin"}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")
	out := w.mustConn3x("plan", "-no-color")
	t.Logf("first plan:\n%s", out)
	if !strings.Contains(out, "Plan: 3 to import, 0 to add, 0 to change, 0 to destroy.") {
		t.Fatalf("the first plan should import all three steps and change nothing:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("the plan after import isn't empty:\n%s", out)
	}

	vars.Zone = "UTC"
	w.writeAs("main.circuit.hcl", vars)
	out = w.mustConn3x("plan", "-no-color")
	t.Logf("plan after changing the time zone:\n%s", out)
	if !strings.Contains(out, "Plan: 0 to add, 1 to change, 0 to destroy.") || !strings.Contains(out, `"Europe/Dublin" -> "UTC"`) {
		t.Fatalf("changing the time zone should plan just that:\n%s", out)
	}
}
