// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// compose_project with podman-compose: up, a second plan clean, a service
// stopped by hand and a file edited by hand both seen and put back, a
// changed file recreating the project, and down on removal.
func TestComposeProject(t *testing.T) {
	box := startHostWith(t, "rocky10", "--privileged")
	// Podman inside a container keeps its images with the vfs driver; see
	// TestContainerStep.
	box.exec("", "sh", "-c", "mkdir -p /etc/containers/storage.conf.d && printf '[storage]\\ndriver = \"vfs\"\\n' | tee /etc/containers/storage.conf > /etc/containers/storage.conf.d/99-vfs.conf")
	knownFile := shareKey(t, box)
	w := newWorkdir(t, "compose_project")
	w.writeAs("main.circuit.hcl", chainVars{PortA: box.port, Key: box.keyFile, KnownHosts: knownFile})
	w.mustConn3x("init", "-no-color")
	running := func() string {
		return strings.TrimSpace(box.exec("", "sh", "-c", `podman ps -a --filter label=io.podman.compose.project=app --format '{{.Names}} {{.State}} {{.Command}}' | sort | tr '\n' ';'`))
	}

	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := running(); got != "app_web_1 running sleep 3600;app_worker_1 running sleep 3601;" {
		t.Fatalf("after the first apply: %q", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes") {
		t.Errorf("a second plan should be clean:\n%s", out)
	}

	box.exec("", "podman", "stop", "-t", "0", "app_worker_1")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "1 to change") {
		t.Errorf("a service stopped by hand should show:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := running(); got != "app_web_1 running sleep 3600;app_worker_1 running sleep 3601;" {
		t.Fatalf("after the stopped service is started: %q", got)
	}

	if out := w.mustConn3x("plan", "-no-color", "-var=worker_sleep=3602"); !strings.Contains(out, "1 to change") {
		t.Errorf("a changed file should plan an up:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=worker_sleep=3602")
	if got := running(); got != "app_web_1 running sleep 3600;app_worker_1 running sleep 3602;" {
		t.Fatalf("after the change: %q", got)
	}

	box.exec("", "sed", "-i", "s/3602/3603/", "/opt/app/compose.yaml")
	if out := w.mustConn3x("plan", "-no-color", "-var=worker_sleep=3602"); !strings.Contains(out, "1 to change") {
		t.Errorf("a file edited by hand should show:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=worker_sleep=3602")
	if got := box.exec("", "grep", "-c", "3602", "/opt/app/compose.yaml"); strings.TrimSpace(got) != "1" {
		t.Errorf("the file should be written back, grep found %q", got)
	}
	if out := w.mustConn3x("plan", "-no-color", "-var=worker_sleep=3602"); !strings.Contains(out, "No changes") {
		t.Errorf("a plan after putting it back should be clean:\n%s", out)
	}

	w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=present=false")
	if got := running(); got != "" {
		t.Errorf("on_remove = delete should take the project down, still have %q", got)
	}
	box.exec("", "test", "-f", "/opt/app/compose.yaml")
}
