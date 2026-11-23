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

type fetchStepVars struct {
	Port, KeyFile, KnownHosts, Token string
	Fetch                            bool
}

// fetch copies a file the same apply made on the host back to the machine
// running Conn3x, owner-only, fetches it again after it changes on either
// side, and deletes the copy when the step goes with on_remove = "delete".
func TestFetchStep(t *testing.T) {
	h := startHost(t, "debian13")
	w := newWorkdir(t, "fetch_step")
	copyPath := filepath.Join(w.dir, "fetched", "box.token")
	got := func() string {
		b, err := os.ReadFile(copyPath)
		if err != nil {
			return "error: " + err.Error()
		}
		return string(b)
	}
	vars := fetchStepVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Token: "first", Fetch: true}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if g := got(); g != "first\n" {
		t.Fatalf("after apply: %q", g)
	}
	if fi, err := os.Stat(copyPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("copy's mode: %v %v", fi.Mode(), err)
	}
	if _, err := os.Stat(filepath.Join(w.dir, "fetched", "box.missing")); !os.IsNotExist(err) {
		t.Errorf("a missing src with fail_on_missing = false wrote something: %v", err)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan:\n%s", out)
	}

	// Changed on the host by the circuit, then by hand here.
	vars.Token = "second"
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if g := got(); g != "second\n" {
		t.Fatalf("after the host's file changed: %q", g)
	}
	if err := os.WriteFile(copyPath, []byte("edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if g := got(); g != "second\n" {
		t.Fatalf("after the copy was edited: %q", g)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan:\n%s", out)
	}

	vars.Fetch = false
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if _, err := os.Stat(copyPath); !os.IsNotExist(err) {
		t.Fatalf("copy still there after removal with on_remove = \"delete\": %v", err)
	}
}
