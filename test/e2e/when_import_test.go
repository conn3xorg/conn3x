// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// A step with import and a when that reads a variable imports when it's
// true and does nothing when it's false (#810).
func TestImportWithWhen(t *testing.T) {
	box := startHost(t, "rocky10")
	box.exec("hello\n", "sh", "-c", "cat > /etc/motd.c3")
	knownFile := shareKey(t, box)
	w := newWorkdir(t, "when_import")
	w.writeAs("main.circuit.hcl", chainVars{PortA: box.port, Key: box.keyFile, KnownHosts: knownFile})
	w.mustConn3x("init", "-no-color")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "Plan: 1 to import, 0 to add, 0 to change, 0 to destroy.") {
		t.Errorf("with when true:\n%s", out)
	}
	if out := w.mustConn3x("plan", "-no-color", "-var=present=false"); !strings.Contains(out, "No changes.") {
		t.Errorf("with when false:\n%s", out)
	}
}
