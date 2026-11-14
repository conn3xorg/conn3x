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

// uri calls an API that listens only on the host, once, with a header kept
// out of state, and again when its body changes.
func TestURI(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "uri")
	w.writeAs("main.circuit.hcl", circuitVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	calls := func() string { return h.exec("", "sh", "-c", "cat /run/api.log 2>/dev/null; true") }
	if got := calls(); got != "Bearer s3cret {\"host\":\"box\",\"version\":\"1\"}\n" {
		t.Fatalf("after apply, the API saw:\n%q", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}
	raw, err := os.ReadFile(filepath.Join(w.dir, "terraform.tfstate"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "s3cret") {
		t.Error("the write-only header is in state")
	}
	if !strings.Contains(string(raw), `"status": 201`) {
		t.Error("state should hold the status")
	}

	// A new body calls again; the same one doesn't.
	w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=release=2")
	if got := calls(); strings.Count(got, "\n") != 2 || !strings.Contains(got, `"version":"2"`) {
		t.Fatalf("after a new version, the API saw:\n%s", got)
	}
}
