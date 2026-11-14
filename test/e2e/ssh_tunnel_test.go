// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type tunnelVars struct {
	Port, KeyFile, KnownHosts string
}

// A conn3x_ssh_tunnel reaches a port only the host can, here its own sshd
// on loopback, for the length of the run, and closes when the run ends.
func TestSSHTunnel(t *testing.T) {
	h := startHost(t, "ubuntu2404")
	w := newWorkdir(t, "ssh_tunnel")
	w.writeAs("main.tf", tunnelVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	banner, err := os.ReadFile(filepath.Join(w.dir, "banner.txt"))
	if err != nil || string(banner) != "SSH-" {
		t.Fatalf("through the tunnel: %q, %v", banner, err)
	}
	port, _ := os.ReadFile(filepath.Join(w.dir, "port.txt"))
	if c, err := net.DialTimeout("tcp", "127.0.0.1:"+strings.TrimSpace(string(port)), time.Second); err == nil {
		c.Close()
		t.Error("the tunnel's port is still open after the run")
	}
	// State names the tunnel only as what terraform_data depends on.
	if state := w.mustConn3x("state", "pull"); strings.Contains(state, "local_port") || strings.Contains(state, "local_host") {
		t.Errorf("the tunnel's values are in state:\n%s", state)
	}
}
