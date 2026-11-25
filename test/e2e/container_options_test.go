// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type containerOptionVars struct{ PortA, Key, KnownHosts, Engine, Package, LogDriver string }

// A container step's user, labels, memory, cpus and log options, with
// Docker on Ubuntu and Podman on Rocky: set by apply, a clean second plan,
// a hand change seen as drift, and apply putting it back (#1352).
func TestContainerOptions(t *testing.T) {
	for _, c := range []struct{ image, engine, pkg, logDriver, logOpt string }{
		{"ubuntu2404", "docker", "docker.io", "json-file", `{"max-size":"10m"}`},
		{"rocky10", "podman", "podman", "k8s-file", "10MB"},
	} {
		t.Run(c.engine, func(t *testing.T) {
			box := startHostWith(t, c.image, "--privileged")
			if c.engine == "podman" {
				// As in TestContainerStep: Podman in a container needs vfs.
				box.exec("", "sh", "-c", "mkdir -p /etc/containers/storage.conf.d && printf '[storage]\\ndriver = \"vfs\"\\n' | tee /etc/containers/storage.conf > /etc/containers/storage.conf.d/99-vfs.conf")
			} else {
				// Overlay can't mount on the host container's overlay either, so
				// dockerd gets vfs, which needs the classic image store.
				box.exec("", "sh", "-c", `mkdir -p /etc/docker && echo '{"storage-driver":"vfs","features":{"containerd-snapshotter":false}}' > /etc/docker/daemon.json`)
			}
			knownFile := shareKey(t, box)
			w := newWorkdir(t, "container_options")
			w.writeAs("main.circuit.hcl", containerOptionVars{box.port, box.keyFile, knownFile, c.engine, c.pkg, c.logDriver})
			w.mustConn3x("init", "-no-color")
			logOpt := "{{json .HostConfig.LogConfig.Config}}"
			if c.engine == "podman" {
				logOpt = "{{.HostConfig.LogConfig.Size}}"
			}
			inspect := func() string {
				return strings.TrimSpace(box.exec("", c.engine, "container", "inspect", "-f",
					`{{.State.Running}} {{.Config.User}} {{index .Config.Labels "traefik.enable"}} {{.HostConfig.Memory}} {{.HostConfig.NanoCpus}} {{.HostConfig.LogConfig.Type}} `+logOpt, "app"))
			}
			want := "true 1000:1000 true 536870912 1500000000 " + c.logDriver + " " + c.logOpt

			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := inspect(); got != want {
				t.Fatalf("after apply: %q, want %q", got, want)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes") {
				t.Errorf("a second plan should be clean:\n%s", out)
			}

			box.exec("", c.engine, "update", "--memory", "256m", "--memory-swap", "512m", "app")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, `app__app["box"] will be updated`) || !strings.Contains(out, "1 to change") {
				t.Errorf("a memory limit changed by hand should show as drift:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := inspect(); got != want {
				t.Errorf("apply should put it back: %q, want %q", got, want)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes") {
				t.Errorf("the plan after apply should be clean:\n%s", out)
			}
		})
	}
}
