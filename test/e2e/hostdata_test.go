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

type hostdataVars struct {
	Port, KeyFile, KnownHosts string
}

// provider::conn3x::hostdata gives each host the value of its highest
// layer: here the group's, until the host gets a file of its own.
func TestHostData(t *testing.T) {
	h := startHost(t, "ubuntu2404")
	w := newWorkdir(t, "hostdata")
	w.writeAs("main.circuit.hcl", hostdataVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts})
	data := filepath.Join(w.dir, "data")
	// Provider functions need their provider in required_providers.
	versions := "terraform {\n  required_providers {\n    conn3x = { source = \"terraform.io/builtin/conn3x\" }\n  }\n}\n"
	if err := os.WriteFile(filepath.Join(w.dir, "versions.tf"), []byte(versions), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"hierarchy.yaml":  "hierarchy:\n  - hosts/{host}.yaml\n  - groups/{group}.yaml\n  - common.yaml\n",
		"common.yaml":     "motd: everyone\n",
		"groups/web.yaml": "motd: a web server\n",
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(data, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(data, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", "/etc/motd.conn3x"); got != "a web server\n" {
		t.Fatalf("motd from the group layer: %q", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}
	if err := os.MkdirAll(filepath.Join(data, "hosts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "hosts", "web1.yaml"), []byte("motd: web1 itself\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", "/etc/motd.conn3x"); got != "web1 itself\n" {
		t.Fatalf("motd once the host has its own layer: %q", got)
	}
}
