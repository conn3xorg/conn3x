// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type circuitVars struct {
	Port, KeyFile, KnownHosts string
	WithIssue                 bool
}

func TestCircuitLifecycle(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "circuit")
	// The template renders to main.circuit.hcl; drop the .tf name the helper uses.
	vars := circuitVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, WithIssue: true}
	w.writeAs("main.circuit.hcl", vars)

	w.mustConn3x("init", "-no-color")
	out := w.mustConn3x("plan", "-no-color")
	for _, want := range []string{
		`conn3x_file.web__motd["web1"] will be created`,
		`conn3x_file.web__issue["web1"] will be created`,
		"2 to add",
		"Conn3x will perform the following actions",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("plan missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "OpenTofu") {
		t.Fatalf("plan output names OpenTofu:\n%s", out)
	}

	w.mustConn3x("apply", "-auto-approve", "-no-color")
	motd := "Hello from web1\n"
	if got := h.exec("", "cat", "/etc/motd"); got != motd {
		t.Fatalf("/etc/motd = %q", got)
	}
	sum := sha256.Sum256([]byte(motd))
	if got := h.exec("", "cat", "/etc/issue.conn3x"); got != "motd sha256 "+hex.EncodeToString(sum[:])+"\n" {
		t.Fatalf("/etc/issue.conn3x = %q", got)
	}
	if got := strings.TrimSpace(h.exec("", "stat", "-c", "%a", "/etc/issue.conn3x")); got != "600" {
		t.Fatalf("mode = %s", got)
	}

	if out = w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("second plan is not empty:\n%s", out)
	}

	// Dropping a step forgets its resource and leaves the file on the host.
	vars.WithIssue = false
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	h.exec("", "test", "-f", "/etc/issue.conn3x")
}

func (w *workdir) writeAs(name string, data any) {
	w.t.Helper()
	w.write(data)
	if err := os.Rename(filepath.Join(w.dir, "main.tf"), filepath.Join(w.dir, name)); err != nil {
		w.t.Fatal(err)
	}
}
