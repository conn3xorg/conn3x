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

// A role that loads vars/<family>.yml converts into one circuit that, on a
// Red Hat host and a Debian-family host together, gives each its own
// family's package, file and service, and plans nothing after.
func TestConvertRoleFamilyVars(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	role := filepath.Join(filepath.Dir(here), "..", "..", "internal", "conn3x", "convert", "ansible", "testdata", "role", "cron")
	rh, deb := startHost(t, "rocky10"), startHost(t, "ubuntu2404")
	known := shareKey(t, rh, deb)

	w := newWorkdir(t, "convert_family")
	if out, code := w.conn3x("convert", "ansible", "-role", role, "-out", "circuit-cron"); code != 0 || !strings.Contains(out, "Converted all 4 tasks.") {
		t.Fatalf("convert exited %d:\n%s", code, out)
	}
	w.writeAs("main.tf", struct{ RHPort, DebPort, Key, KnownHosts string }{rh.port, deb.port, rh.keyFile, known})
	w.mustConn3x("init", "-no-color")
	out := w.mustConn3x("apply", "-auto-approve", "-no-color")
	t.Logf("apply:\n%s", out)

	checks := map[*host]string{
		rh:  "rpm -q --qf '%{NAME}\\n' cronie; cat /etc/sysconfig/cron-role; systemctl is-active crond",
		deb: "dpkg-query -W -f '${Package}\\n' cron; cat /etc/default/cron-role; systemctl is-active cron",
	}
	wants := map[*host]string{
		rh:  "cronie\n# Managed by the cron role\nactive\n",
		deb: "cron\n# Managed by the cron role\nactive\n",
	}
	for h, cmd := range checks {
		if got := h.exec("", "sh", "-c", cmd); got != wants[h] {
			t.Errorf("host after apply:\n%s\nwant\n%s", got, wants[h])
		}
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}
}
