// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// A modprobe step loads ifb with its parameters, loads it again when they
// change, and unloads it. A module loads into the machine's kernel, so this
// runs only when CONN3X_E2E_MODPROBE is set, with a container engine that
// runs as root and the kernel's modules at /lib/modules:
//
//	CONTAINER_CONNECTION=podman-machine-default-root CONN3X_E2E_MODPROBE=1 go test -tags e2e ./test/e2e -run TestModprobe
func TestModprobeStep(t *testing.T) {
	if os.Getenv("CONN3X_E2E_MODPROBE") == "" {
		t.Skip("set CONN3X_E2E_MODPROBE; see the comment above")
	}
	box := startHostWith(t, "rocky10", "--privileged", "-v", "/lib/modules:/lib/modules:ro")
	t.Cleanup(func() { _ = exec.Command("podman", "exec", box.container, "modprobe", "-r", "ifb").Run() })
	knownFile := shareKey(t, box)
	w := newWorkdir(t, "modprobe")
	w.writeAs("main.circuit.hcl", chainVars{PortA: box.port, Key: box.keyFile, KnownHosts: knownFile})
	w.mustConn3x("init", "-no-color")
	// ifb doesn't show numifbs in /sys/module, so the options file is what
	// says which value it was loaded with.
	loaded := func() bool { return strings.Contains(box.exec("", "cat", "/proc/modules"), "ifb ") }
	options := func() string {
		return strings.TrimSpace(box.exec("", "sh", "-c", "grep -h '^options' /etc/modprobe.d/ifb.conf 2>/dev/null || true"))
	}

	w.mustConn3x("apply", "-auto-approve", "-no-color", `-var=params=["numifbs=1"]`)
	if !loaded() || options() != "options ifb numifbs=1" {
		t.Fatalf("loaded %v, options %q", loaded(), options())
	}
	if got := box.exec("", "cat", "/etc/modules-load.d/ifb.conf"); !strings.Contains(got, "ifb\n") {
		t.Errorf("modules-load.d:\n%s", got)
	}
	if out := w.mustConn3x("plan", "-no-color", `-var=params=["numifbs=1"]`); !strings.Contains(out, "No changes") {
		t.Errorf("a second plan should be clean:\n%s", out)
	}

	w.mustConn3x("apply", "-auto-approve", "-no-color", `-var=params=["numifbs=2"]`)
	if !loaded() || options() != "options ifb numifbs=2" {
		t.Errorf("after changing params: loaded %v, options %q", loaded(), options())
	}

	w.mustConn3x("apply", "-auto-approve", "-no-color", `-var=params=[]`, "-var=state=absent")
	if loaded() {
		t.Error("state absent should unload it")
	}
	if out := box.exec("", "sh", "-c", "ls /etc/modules-load.d /etc/modprobe.d"); strings.Contains(out, "ifb.conf") {
		t.Errorf("the boot files should be gone:\n%s", out)
	}
}
