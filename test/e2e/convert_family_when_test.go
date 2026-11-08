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

// A role's when on the family becomes the step's when: on a Red Hat host
// and a Debian-family host together, each runs only its own family's
// steps, and the next plan is empty.
func TestConvertRoleFamilyWhen(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	role := filepath.Join(filepath.Dir(here), "..", "..", "internal", "conn3x", "convert", "ansible", "testdata", "role", "famwhen")
	rh, deb := startHost(t, "rocky10"), startHost(t, "ubuntu2404")
	known := shareKey(t, rh, deb)

	w := newWorkdir(t, "convert_family_when")
	out, _ := w.conn3x("convert", "ansible", "-role", role, "-out", "circuit-famwhen")
	if !strings.Contains(out, "Converted 3 tasks.") {
		t.Fatalf("convert:\n%s", out)
	}
	w.writeAs("main.tf", struct{ RHPort, DebPort, Key, KnownHosts string }{rh.port, deb.port, rh.keyFile, known})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	check := "for p in /etc/famwhen-debian /srv/famwhen-redhat; do test -e $p && echo $p; done; true"
	if got := rh.exec("", "sh", "-c", check); got != "/srv/famwhen-redhat\n" {
		t.Errorf("rocky has %q, want only the Red Hat step's directory", got)
	}
	if got := deb.exec("", "sh", "-c", check); got != "/etc/famwhen-debian\n" {
		t.Errorf("ubuntu has %q, want only the Debian step's file", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}
}
