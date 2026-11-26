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

// A role's stat probe becomes a conn3x_command data source testing the
// path: the steps whose when read X.stat.exists run for a file that exists
// and not for one that doesn't, and a dangling link counts as there, as
// stat's default follow: false has it (#1344).
func TestConvertRoleStatProbe(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	role := filepath.Join(filepath.Dir(here), "..", "..", "internal", "conn3x", "convert", "ansible", "testdata", "role", "stat")
	for _, image := range []string{"debian13", "rocky10"} {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "convert_stat")
			if out, code := w.conn3x("convert", "ansible", "-role", role, "-out", "circuit-stat"); code != 0 || !strings.Contains(out, "Converted all 5 tasks.") {
				t.Fatalf("convert exited %d:\n%s", code, out)
			}
			w.write(struct{ Port, Key, KnownHosts string }{h.port, h.keyFile, h.knownHosts})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			check := "for p in /tmp/stat-passwd-seen /tmp/stat-missing-seen /tmp/stat-app.conf; do test -e $p && echo $p; done; true"
			if got := h.exec("", "sh", "-c", check); got != "/tmp/stat-passwd-seen\n/tmp/stat-app.conf\n" {
				t.Fatalf("host after apply has %q; want the steps for /etc/passwd there and /tmp/stat-missing missing", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			// A dangling link exists to stat, so the missing-file step runs.
			// The config its when now skips stays: a file step forgets what
			// it wrote on removal.
			h.exec("", "ln", "-s", "/nonexistent", "/tmp/stat-missing")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "sh", "-c", check); got != "/tmp/stat-passwd-seen\n/tmp/stat-missing-seen\n/tmp/stat-app.conf\n" {
				t.Fatalf("host after the link appeared has %q; want the step for a found path too", got)
			}
		})
	}
}
