// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// A container step with Podman: made, left alone by a second plan, made
// again for a new image tag, started after it's stopped, and removed.
func TestContainerStep(t *testing.T) {
	box := startHostWith(t, "rocky10", "--privileged")
	// Podman inside a container keeps its images with the vfs driver. Podman 6
	// reads a vendor drop-in that picks overlay after storage.conf, so the
	// setting goes in a drop-in too; Podman 5 reads only storage.conf.
	box.exec("", "sh", "-c", "mkdir -p /etc/containers/storage.conf.d /srv/c3 && printf '[storage]\\ndriver = \"vfs\"\\n' | tee /etc/containers/storage.conf > /etc/containers/storage.conf.d/99-vfs.conf")
	pullThroughMirror(box)
	knownFile := shareKey(t, box)
	w := newWorkdir(t, "container")
	w.writeAs("main.circuit.hcl", chainVars{PortA: box.port, Key: box.keyFile, KnownHosts: knownFile})
	w.mustConn3x("init", "-no-color")
	inspect := func() string {
		return strings.TrimSpace(box.exec("", "podman", "inspect", "-f", "{{.State.Running}} {{.Config.Image}}", "web"))
	}

	w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=image=docker.io/library/busybox:1.36")
	if got := inspect(); got != "true docker.io/library/busybox:1.36" {
		t.Fatalf("after the first apply: %q", got)
	}
	if got := strings.TrimSpace(box.exec("", "cat", "/srv/c3/greeting")); got != "hello" {
		t.Errorf("env and volume: greeting = %q", got)
	}
	if out := w.mustConn3x("plan", "-no-color", "-var=image=docker.io/library/busybox:1.36"); !strings.Contains(out, "No changes") {
		t.Errorf("a second plan should be clean:\n%s", out)
	}

	// Another configuration adopts the container with import.
	adopt := newWorkdir(t, "container_import")
	adopt.writeAs("main.circuit.hcl", chainVars{PortA: box.port, Key: box.keyFile, KnownHosts: knownFile})
	adopt.mustConn3x("init", "-no-color")
	if out := adopt.mustConn3x("plan", "-no-color", "-var=image=docker.io/library/busybox:1.36"); !strings.Contains(out, "Plan: 1 to import, 0 to add, 0 to change, 0 to destroy.") {
		t.Errorf("importing the container:\n%s", out)
	}

	w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=image=docker.io/library/busybox:1.37")
	if got := inspect(); got != "true docker.io/library/busybox:1.37" {
		t.Errorf("a new tag should recreate it: %q", got)
	}

	box.exec("", "podman", "stop", "-t", "0", "web")
	if out := w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=image=docker.io/library/busybox:1.37"); !strings.Contains(out, "1 changed") {
		t.Errorf("a stopped container should be started:\n%s", out)
	}
	if got := inspect(); got != "true docker.io/library/busybox:1.37" {
		t.Errorf("after starting it again: %q", got)
	}

	w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=image=docker.io/library/busybox:1.37", "-var=present=false")
	if got := strings.TrimSpace(box.exec("", "sh", "-c", "podman ps -a --format '{{.Names}}'")); got != "" {
		t.Errorf("on_remove = delete should remove it, still have %q", got)
	}
}

// pullThroughMirror has Podman on box fetch docker.io images through
// Google's mirror of Docker Hub, which CI reaches without Docker Hub's
// unauthenticated pull limit ("toomanyrequests", 27 Nov). Image names
// stay docker.io/..., so what the tests check doesn't change.
func pullThroughMirror(box *host) {
	box.exec("", "sh", "-c", "mkdir -p /etc/containers/registries.conf.d && printf '[[registry]]\\nprefix = \"docker.io\"\\nlocation = \"docker.io\"\\n\\n[[registry.mirror]]\\nlocation = \"mirror.gcr.io\"\\n' > /etc/containers/registries.conf.d/99-mirror.conf")
}
