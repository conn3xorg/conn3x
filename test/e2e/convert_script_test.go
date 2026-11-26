// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A role's script task becomes a command step that runs the script once:
// the script reads nothing of itself on stdin, creates holds it off after,
// even once the script changes, and nothing is left in /tmp (#1346).
func TestConvertRoleScript(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	role := filepath.Join(filepath.Dir(here), "..", "..", "internal", "conn3x", "convert", "ansible", "testdata", "role", "script")
	for _, image := range []string{"debian13", "rocky10"} {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "convert_script")
			if out, code := w.conn3x("convert", "ansible", "-role", role, "-out", "circuit-script"); code != 0 || !strings.Contains(out, "Converted the 1 task.") {
				t.Fatalf("convert exited %d:\n%s", code, out)
			}
			w.write(struct{ Port, Key, KnownHosts string }{h.port, h.keyFile, h.knownHosts})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "cat", "/opt/app/runs"); got != "run unasked\n" {
				t.Fatalf("runs after apply is %q; want one run that read nothing on stdin", got)
			}
			if got := h.exec("", "find", "/tmp", "-maxdepth", "1", "-name", "tmp.*"); got != "" {
				t.Fatalf("mktemp's file is left in /tmp: %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			// A changed script plans the step again, but creates still holds.
			script := filepath.Join(w.dir, "circuit-script", "files", "setup.sh")
			b, err := os.ReadFile(script)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(script, append(b, "echo changed >>\"$2/runs\"\n"...), 0o644); err != nil {
				t.Fatal(err)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "cat", "/opt/app/runs"); got != "run unasked\n" {
				t.Fatalf("runs after the script changed is %q; creates should have held it off", got)
			}
		})
	}
}
