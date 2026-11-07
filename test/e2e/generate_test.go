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

// conn3x generate step prints steps for what a host already has; pasted
// into a circuit, they import with nothing to change and the next plan is
// empty. Content that isn't text, and write-only content, stays out of the
// output, and an object the host doesn't have is an error.
func TestGenerateStep(t *testing.T) {
	h := startHost(t, "rocky10")
	h.exec("Welcome ${user}\n", "sh", "-c", "cat > /etc/motd && chmod 0640 /etc/motd && chgrp wheel /etc/motd")
	h.exec("", "sh", "-c", "head -c 64 /dev/urandom > /etc/blob")
	h.exec("s3cret-token\n", "sh", "-c", "cat > /etc/app-token && chmod 0600 /etc/app-token")
	h.exec("", "dnf", "-y", "-q", "install", "tree")
	h.exec("", "useradd", "-s", "/bin/sh", "deploy")

	w := newWorkdir(t, "generate")
	gen := func(args ...string) string {
		t.Helper()
		base := []string{"generate", "step", "-host", "127.0.0.1", "-port", h.port, "-user", "root",
			"-private-key-file", h.keyFile, "-known-hosts-file", h.knownHosts}
		out, code := w.conn3x(append(base, args...)...)
		if code != 0 {
			t.Fatalf("generate %v exited %d:\n%s", args, code, out)
		}
		t.Logf("generate %v:\n%s", args, out)
		return out
	}
	steps := gen("file", "path=/etc/motd") + gen("package", "name=tree") +
		gen("service", "name=sshd") + gen("user", "name=deploy")
	if !strings.Contains(steps, `step "etc_motd"`) || !strings.Contains(steps, `"wheel"`) || !strings.Contains(steps, "Welcome $${user}") {
		t.Fatalf("the file step doesn't say what the host has:\n%s", steps)
	}

	if out := gen("file", "path=/etc/blob"); !strings.Contains(out, "isn't UTF-8") || !strings.Contains(out, `content_wo = "REPLACE ME"`) {
		t.Fatalf("binary content should become a placeholder:\n%s", out)
	}
	if out := gen("-write-only", "-name", "token", "file", "path=/etc/app-token"); strings.Contains(out, "s3cret") || !strings.Contains(out, `content_wo = "REPLACE ME"`) {
		t.Fatalf("write-only content reached the output:\n%s", out)
	}
	out, code := w.conn3x("generate", "step", "-host", "127.0.0.1", "-port", h.port, "-user", "root",
		"-private-key-file", h.keyFile, "-known-hosts-file", h.knownHosts, "file", "path=/etc/not-here")
	if code != 1 || !strings.Contains(out, "127.0.0.1 doesn't have file /etc/not-here") {
		t.Fatalf("a missing file should be an error (exit %d):\n%s", code, out)
	}

	w.writeAs("main.circuit.hcl", struct{ Port, KeyFile, KnownHosts string }{h.port, h.keyFile, h.knownHosts})
	path := filepath.Join(w.dir, "main.circuit.hcl")
	circuit, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(circuit), "# steps", steps, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	w.mustConn3x("init", "-no-color")
	out = w.mustConn3x("plan", "-no-color")
	t.Logf("first plan:\n%s", out)
	if !strings.Contains(out, "Plan: 4 to import, 0 to add, 0 to change, 0 to destroy.") {
		t.Fatalf("the generated steps should import with nothing to change:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("the plan after import isn't empty:\n%s", out)
	}
}
