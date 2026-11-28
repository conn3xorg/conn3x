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

// A role's probes after a task that changes the host become circuit
// probes, read during the apply after that task, and the whens on them
// only_if: the first apply follows what the host says once the config is
// written, and the next plan is clean. A when on "is changed" becomes
// triggers on the registering step's revision.
func TestConvertRoleProbeAfterChanges(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	role := filepath.Join(filepath.Dir(here), "..", "..", "internal", "conn3x", "convert", "ansible", "testdata", "role", "probe_late")
	h := startHost(t, "debian13")
	w := newWorkdir(t, "convert_probe_late")
	if out, code := w.conn3x("convert", "ansible", "-role", role, "-out", "circuit-probe-late"); code != 0 || !strings.Contains(out, "Converted all 8 tasks.") {
		t.Fatalf("convert exited %d:\n%s", code, out)
	}
	w.write(struct{ Port, Key, KnownHosts string }{h.port, h.keyFile, h.knownHosts})
	w.mustConn3x("init", "-no-color")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, `data.conn3x_command.probe_late__conf["box"] will be read during apply`) {
		t.Fatalf("the probe after the config step doesn't wait for the apply:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	lines := func(p string) int {
		return strings.Count(h.exec("", "sh", "-c", "cat "+p+" 2>/dev/null || true"), "\n")
	}
	check := "for p in /etc/late-found /etc/late-missing /usr/local/bin/late-tool; do test -e $p && echo $p; done; true"
	if got := h.exec("", "sh", "-c", check); got != "/etc/late-found\n/usr/local/bin/late-tool\n" {
		t.Fatalf("host after apply has %q; want the step for a found config and the tool", got)
	}
	if lines("/var/log/late.installs") != 1 || lines("/var/log/late.formats") != 1 {
		t.Fatalf("installs %d, formats %d; want 1 each", lines("/var/log/late.installs"), lines("/var/log/late.formats"))
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}

	// The tool is removed by hand: the probe says so, and the install,
	// whose creates no longer holds, runs again. The data file is still
	// there, so formatting doesn't.
	h.exec("", "rm", "/usr/local/bin/late-tool")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if lines("/var/log/late.installs") != 2 || lines("/var/log/late.formats") != 1 {
		t.Fatalf("installs %d, formats %d; want 2 and 1", lines("/var/log/late.installs"), lines("/var/log/late.formats"))
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after the reinstall:\n%s", out)
	}
}
