// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os/exec"
	"strings"
	"testing"
)

type accountVars struct {
	Port, KeyFile, KnownHosts string
	WithUser                  bool
}

func TestAccountLifecycle(t *testing.T) {
	for _, image := range []string{"rocky10", "ubuntu2404"} {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "account")
			vars := accountVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, WithUser: true}
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			if got := strings.TrimSpace(h.exec("", "getent", "group", "ops")); !strings.HasPrefix(got, "ops:x:2500:") || !strings.Contains(got, "alice") {
				t.Fatalf("getent group ops = %q", got)
			}
			if got := strings.TrimSpace(h.exec("", "getent", "passwd", "alice")); !strings.HasSuffix(got, ":/bin/sh") {
				t.Fatalf("getent passwd alice = %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply is not empty:\n%s", out)
			}

			h.exec("", "usermod", "-s", "/bin/bash", "alice")
			out := w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, `conn3x_user.people__alice["box"] will be updated in-place`) || !strings.Contains(out, `"/bin/bash" -> "/bin/sh"`) {
				t.Fatalf("drift plan:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			vars.WithUser = false
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if exec.Command("podman", "exec", h.container, "getent", "passwd", "alice").Run() == nil {
				t.Fatal("alice still exists after removal with on_remove = delete")
			}
			h.exec("", "test", "-d", "/home/alice")
		})
	}
}
