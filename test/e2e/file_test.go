// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type fileVars struct {
	Content, OnRemove, Port, KeyFile, KnownHosts string
}

func TestFileLifecycle(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "file")
	vars := fileVars{Content: `Welcome to a Conn3x host\n`, Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts}
	w.write(vars)

	out := w.mustConn3x("init", "-no-color")
	if strings.Contains(out, "registry") && strings.Contains(out, "conn3x") {
		t.Fatalf("init looked up conn3x in a registry:\n%s", out)
	}

	out = w.mustConn3x("plan", "-no-color")
	for _, want := range []string{`+ resource "conn3x_file" "motd"`, "1 to add"} {
		if !strings.Contains(out, want) {
			t.Fatalf("plan missing %q:\n%s", want, out)
		}
	}

	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", "/etc/motd"); got != "Welcome to a Conn3x host\n" {
		t.Fatalf("/etc/motd = %q", got)
	}

	if out = w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("second plan is not empty:\n%s", out)
	}

	h.exec("", "sh", "-c", "echo hacked > /etc/motd")
	out = w.mustConn3x("plan", "-no-color")
	for _, want := range []string{`~ resource "conn3x_file" "motd"`, "1 to change", "hacked"} {
		if !strings.Contains(out, want) {
			t.Fatalf("drift plan missing %q:\n%s", want, out)
		}
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", "/etc/motd"); got != "Welcome to a Conn3x host\n" {
		t.Fatalf("drift not repaired: /etc/motd = %q", got)
	}

	// Removing the resource forgets the file and leaves it on the host.
	if err := writeEmpty(w); err != nil {
		t.Fatal(err)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", "/etc/motd"); got != "Welcome to a Conn3x host\n" {
		t.Fatalf("file changed after removing the resource: %q", got)
	}
}

func TestFileUnknownHostKeyFailsApply(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "file")
	empty := t.TempDir() + "/known_hosts"
	vars := fileVars{Content: "x", Port: h.port, KeyFile: h.keyFile, KnownHosts: empty}
	if err := touch(empty); err != nil {
		t.Fatal(err)
	}
	w.write(vars)
	w.mustConn3x("init", "-no-color")
	// Plan itself never contacts a host for a new resource, so apply is where
	// the unknown key must stop it.
	out, code := w.conn3x("apply", "-auto-approve", "-no-color")
	if code == 0 {
		t.Fatalf("apply succeeded against an unknown host key:\n%s", out)
	}
	if !strings.Contains(out, "127.0.0.1:"+h.port) || !strings.Contains(out, "known_hosts") {
		t.Fatalf("error does not name the host and known_hosts file:\n%s", out)
	}
	if got := h.exec("", "cat", "/etc/motd"); got == "x" {
		t.Fatal("file was written despite the host key failure")
	}
}
