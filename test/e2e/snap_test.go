// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os/exec"
	"strings"
	"testing"
)

type snapVars struct {
	Port, KeyFile, KnownHosts, Channel string
}

// TestSnap installs a snap on a channel, moves it to another, and removes
// it, on Ubuntu with a real snapd. snapd mounts each snap's squashfs and
// talks to systemd, which a container only allows with --privileged, and
// in a container it mounts through squashfuse rather than the kernel.
func TestSnap(t *testing.T) {
	h := startHostWith(t, "ubuntu2404", "--privileged")
	// Some CI runners refuse snapd's or fuse's install scripts even with
	// --privileged, which says nothing about the snap step, so skip there.
	if out, err := exec.Command("podman", "exec", h.container, "bash", "-o", "pipefail", "-c", "{ apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq squashfuse fuse snapd; } 2>&1 | tail -40").CombinedOutput(); err != nil {
		t.Skipf("snapd doesn't install in this container, so the snap step needs a VM to test: %v\n%s", err, out)
	}
	h.exec("", "systemctl", "start", "snapd.socket", "snapd.service")
	if out, err := exec.Command("podman", "exec", h.container, "timeout", "120", "snap", "wait", "system", "seed.loaded").CombinedOutput(); err != nil {
		t.Skipf("snapd doesn't run in this container, so the snap step needs a VM to test: %v\n%s", err, out)
	}

	w := newWorkdir(t, "snap")
	w.writeAs("main.circuit.hcl", snapVars{h.port, h.keyFile, h.knownHosts, "stable"})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if out := h.exec("", "snap", "list", "--unicode=never", "--color=never", "hello-world"); !strings.Contains(out, "latest/stable") {
		t.Fatalf("after apply:\n%s", out)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}

	w.writeAs("main.circuit.hcl", snapVars{h.port, h.keyFile, h.knownHosts, "latest/edge"})
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if out := h.exec("", "snap", "list", "--unicode=never", "--color=never", "hello-world"); !strings.Contains(out, "latest/edge") {
		t.Fatalf("after the channel change:\n%s", out)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after the change:\n%s", out)
	}

	w.writeAs("main.circuit.hcl", snapVars{h.port, h.keyFile, h.knownHosts, ""})
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if out, err := exec.Command("podman", "exec", h.container, "snap", "list", "hello-world").CombinedOutput(); err == nil || !strings.Contains(string(out), "no matching snaps installed") {
		t.Fatalf("after removal: %v\n%s", err, out)
	}
}
