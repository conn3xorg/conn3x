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

// A role's probe, a read-only command whose result later tasks test,
// becomes a conn3x_command data source: the steps whose when read it run,
// or don't, by what the host answered at plan time, and once the host
// changes, the next apply follows the new answer.
func TestConvertRoleProbe(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	role := filepath.Join(filepath.Dir(here), "..", "..", "internal", "conn3x", "convert", "ansible", "testdata", "role", "probe")
	h := startHost(t, "ubuntu2404")
	w := newWorkdir(t, "convert_probe")
	if out, code := w.conn3x("convert", "ansible", "-role", role, "-out", "circuit-probe"); code != 0 || !strings.Contains(out, "Converted all 5 tasks.") {
		t.Fatalf("convert exited %d:\n%s", code, out)
	}
	w.write(struct{ Port, Key, KnownHosts string }{h.port, h.keyFile, h.knownHosts})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	check := "for p in /etc/probe-missing /etc/probe-found /etc/probe-linux; do test -e $p && echo $p; done; true"
	if got := h.exec("", "sh", "-c", check); got != "/etc/probe-missing\n/etc/probe-linux\n" {
		t.Fatalf("host after apply has %q; want the step for a missing marker and the Linux one", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}

	// The probe reads the marker now, so the other step runs. The file the
	// first one wrote stays: a file step forgets what it wrote on removal.
	h.exec("", "touch", "/etc/probe-marker")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "sh", "-c", check); got != "/etc/probe-missing\n/etc/probe-found\n/etc/probe-linux\n" {
		t.Fatalf("host after the marker appeared has %q; want the step for a found marker too", got)
	}
}
