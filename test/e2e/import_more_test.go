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

type importMoreVars struct {
	Port, KeyFile, KnownHosts string
	Import                    bool
	Schedule                  string
	Missing                   bool
}

// The modules whose read reports only in_sync: a first apply makes the
// objects, the state is thrown away, and the same steps with import = true
// adopt them with nothing to change. Then the next plan is empty, a
// different schedule plans just that change, and a cron job the host
// doesn't have fails the plan instead of being created.
func TestStepImportSyncedModules(t *testing.T) {
	// --privileged for the sysctl and the tmpfs mount, as in sysctl_test.go.
	h := startHostWith(t, "rocky10", "--privileged")
	h.exec("", "dnf", "-y", "-q", "install", "procps-ng", "cronie")
	h.exec("", "useradd", "deploy")

	w := newWorkdir(t, "import_more")
	vars := importMoreVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Schedule: "@daily"}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if err := os.Remove(filepath.Join(w.dir, "terraform.tfstate")); err != nil {
		t.Fatal(err)
	}

	vars.Import = true
	w.writeAs("main.circuit.hcl", vars)
	out := w.mustConn3x("plan", "-no-color")
	t.Logf("first plan:\n%s", out)
	if !strings.Contains(out, "Plan: 6 to import, 0 to add, 0 to change, 0 to destroy.") {
		t.Fatalf("the first plan should import all six steps and change nothing:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("the plan after import isn't empty:\n%s", out)
	}

	vars.Schedule = "@hourly"
	w.writeAs("main.circuit.hcl", vars)
	out = w.mustConn3x("plan", "-no-color")
	t.Logf("plan after changing the schedule:\n%s", out)
	if !strings.Contains(out, "Plan: 0 to add, 1 to change, 0 to destroy.") || !strings.Contains(out, `"@daily" -> "@hourly"`) {
		t.Fatalf("changing the schedule should plan just that:\n%s", out)
	}

	vars.Schedule, vars.Missing = "@daily", true
	w.writeAs("main.circuit.hcl", vars)
	out, code := w.conn3x("plan", "-no-color")
	t.Logf("plan with a missing cron job:\n%s", out)
	if code == 0 || !strings.Contains(out, "Nothing to import on box") || !strings.Contains(out, "cron job not-here") {
		t.Fatalf("importing a cron job the host doesn't have should fail the plan (exit %d):\n%s", code, out)
	}
}
