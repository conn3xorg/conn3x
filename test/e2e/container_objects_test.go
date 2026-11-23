// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// container_image, container_network and container_volume with Podman:
// made, made again after they go by hand, a container run on the network
// and the volume, a second plan clean, and all of it removed in reverse.
func TestContainerObjects(t *testing.T) {
	box := startHostWith(t, "rocky10", "--privileged")
	// Podman inside a container keeps its images with the vfs driver; see
	// TestContainerStep.
	box.exec("", "sh", "-c", "mkdir -p /etc/containers/storage.conf.d && printf '[storage]\\ndriver = \"vfs\"\\n' | tee /etc/containers/storage.conf > /etc/containers/storage.conf.d/99-vfs.conf")
	knownFile := shareKey(t, box)
	w := newWorkdir(t, "container_objects")
	w.writeAs("main.circuit.hcl", chainVars{PortA: box.port, Key: box.keyFile, KnownHosts: knownFile})
	w.mustConn3x("init", "-no-color")
	exist := func() string {
		return strings.TrimSpace(box.exec("", "sh", "-c", `for x in "image exists docker.io/library/busybox:1.37" "network exists app" "volume exists data"; do podman $x && echo yes || echo no; done | tr '\n' ' '`))
	}

	w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=web=false")
	if got := exist(); got != "yes yes yes" {
		t.Fatalf("after the first apply, image, network and volume: %q", got)
	}
	if got := strings.TrimSpace(box.exec("", "podman", "network", "inspect", "-f", "{{range .Subnets}}{{.Subnet}}{{end}}", "app")); got != "10.89.7.0/24" {
		t.Errorf("subnet = %q", got)
	}

	box.exec("", "sh", "-c", "podman image rm docker.io/library/busybox:1.37 && podman network rm app && podman volume rm data")
	if out := w.mustConn3x("plan", "-no-color", "-var=web=false"); !strings.Contains(out, "3 to change") {
		t.Errorf("what went by hand should show:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=web=false")
	if got := exist(); got != "yes yes yes" {
		t.Fatalf("after they're made again: %q", got)
	}

	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := strings.TrimSpace(box.exec("", "podman", "inspect", "-f", "{{.State.Running}} {{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}", "web")); got != "true app" {
		t.Errorf("the container on the network: %q", got)
	}
	if got := strings.TrimSpace(box.exec("", "podman", "exec", "web", "cat", "/data/greeting")); got != "hello" {
		t.Errorf("the container on the volume: greeting = %q", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes") {
		t.Errorf("a second plan should be clean:\n%s", out)
	}

	// The container goes first, or the engine wouldn't remove the rest.
	w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=present=false")
	if got := exist(); got != "no no no" {
		t.Errorf("on_remove = delete should remove them all: %q", got)
	}
	if got := strings.TrimSpace(box.exec("", "sh", "-c", "podman ps -a --format '{{.Names}}'")); got != "" {
		t.Errorf("the container should be gone, still have %q", got)
	}
}
