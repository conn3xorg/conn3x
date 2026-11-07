// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type importVars struct {
	Port, KeyFile, KnownHosts string
	Mode                      string
	Missing                   bool
}

// A step with import = true adopts what is already on the host: the plan
// imports without changing anything, a write-only file's content stays out
// of state, the next plan is empty, and changing one argument plans just
// that change. A host that lacks the object fails the plan instead of
// creating it.
func TestStepImport(t *testing.T) {
	h := startHost(t, "rocky10")
	h.exec("Welcome\n", "sh", "-c", "cat > /etc/motd && chmod 0644 /etc/motd")
	h.exec("s3cret-token\n", "sh", "-c", "cat > /etc/app-token && chmod 0600 /etc/app-token")
	h.exec("", "dnf", "-y", "-q", "install", "tree")
	h.exec("", "groupadd", "ops")
	h.exec("", "useradd", "-G", "ops", "deploy")

	w := newWorkdir(t, "import")
	vars := importVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Mode: "0644"}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")

	out := w.mustConn3x("plan", "-no-color")
	t.Logf("first plan:\n%s", out)
	if !strings.Contains(out, "Plan: 6 to import, 0 to add, 0 to change, 0 to destroy.") {
		t.Fatalf("the first plan should import all six steps and change nothing:\n%s", out)
	}
	if strings.Contains(out, "s3cret") {
		t.Fatal("the write-only content shows in the plan")
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	state, err := os.ReadFile(filepath.Join(w.dir, "terraform.tfstate"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state), "s3cret") {
		t.Fatal("the write-only file's content reached state")
	}

	out = w.mustConn3x("plan", "-no-color")
	if !strings.Contains(out, "No changes.") {
		t.Fatalf("the plan after import isn't empty:\n%s", out)
	}

	vars.Mode = "0640"
	w.writeAs("main.circuit.hcl", vars)
	out = w.mustConn3x("plan", "-no-color")
	t.Logf("plan after changing mode:\n%s", out)
	// One " -> " is the legend's "(current -> planned)", the other the mode.
	if !strings.Contains(out, "Plan: 0 to add, 1 to change, 0 to destroy.") || !strings.Contains(out, `"0644" -> "0640"`) || strings.Count(out, " -> ") != 2 {
		t.Fatalf("changing mode should plan just that:\n%s", out)
	}

	vars.Mode, vars.Missing = "0644", true
	w.writeAs("main.circuit.hcl", vars)
	out, code := w.conn3x("plan", "-no-color")
	t.Logf("plan with a missing file:\n%s", out)
	if code == 0 || !strings.Contains(out, "Nothing to import on box") || !strings.Contains(out, "/etc/not-here") {
		t.Fatalf("importing a file the host doesn't have should fail the plan (exit %d):\n%s", code, out)
	}
}
