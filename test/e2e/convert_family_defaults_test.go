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

type familyDefaultVars struct {
	RHPort, DebPort, Key, KnownHosts, User string
}

// A per-family default the caller can override: without the variable each
// host gets its family's owner, and with it both get the caller's.
func TestConvertRoleFamilyDefaults(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	role := filepath.Join(filepath.Dir(here), "..", "..", "internal", "conn3x", "convert", "ansible", "testdata", "role", "svc")
	rh, deb := startHost(t, "rocky10"), startHost(t, "ubuntu2404")
	known := shareKey(t, rh, deb)

	w := newWorkdir(t, "convert_family_defaults")
	if out, code := w.conn3x("convert", "ansible", "-role", role, "-out", "circuit-svc"); code != 0 || !strings.Contains(out, "Converted all 3 tasks.") {
		t.Fatalf("convert exited %d:\n%s", code, out)
	}
	vars := familyDefaultVars{RHPort: rh.port, DebPort: deb.port, Key: rh.keyFile, KnownHosts: known}
	owner := func(h *host) string { return strings.TrimSpace(h.exec("", "stat", "-c", "%U", "/srv/svc")) }

	w.writeAs("main.tf", vars)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if a, b := owner(rh), owner(deb); a != "nobody" || b != "www-data" {
		t.Fatalf("owners = %s on rocky, %s on ubuntu; want each family's", a, b)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}

	vars.User = "daemon"
	w.writeAs("main.tf", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if a, b := owner(rh), owner(deb); a != "daemon" || b != "daemon" {
		t.Fatalf("owners = %s on rocky, %s on ubuntu; want the caller's daemon on both", a, b)
	}
}
