// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A role that includes its tasks by family converts into steps that run
// only on their family's hosts: the per-family setup file, and a file
// included with a when on the family.
func TestConvertRoleFamilyInclude(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	role := filepath.Join(filepath.Dir(here), "..", "..", "internal", "conn3x", "convert", "ansible", "testdata", "role", "famincl")
	rh, deb := startHost(t, "rocky10"), startHost(t, "ubuntu2404")
	known := shareKey(t, rh, deb)

	w := newWorkdir(t, "convert_family_include")
	if out, _ := w.conn3x("convert", "ansible", "-role", role, "-out", "circuit-famincl"); !strings.Contains(out, "Converted 3 tasks.") {
		t.Fatalf("convert:\n%s", out)
	}
	w.writeAs("main.tf", struct{ RHPort, DebPort, Key, KnownHosts string }{rh.port, deb.port, rh.keyFile, known})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	check := "for p in /etc/famincl-debian /etc/famincl-redhat /etc/famincl-extra /etc/famincl-arch; do test -e $p && echo $p; done; true"
	if got := rh.exec("", "sh", "-c", check); got != "/etc/famincl-redhat\n" {
		t.Errorf("rocky has %q, want only the Red Hat setup", got)
	}
	if got := deb.exec("", "sh", "-c", check); got != "/etc/famincl-debian\n/etc/famincl-extra\n" {
		t.Errorf("ubuntu has %q, want the Debian setup and extra", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}
}
