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

type importModuleVars struct{ Port, KeyFile, KnownHosts string }

// A circuit used as a module, as an official circuit is, adopts what a host
// already has through a root import block whose ID provider::conn3x::import_id
// builds: the plan imports without changing anything, and the next is empty.
func TestImportIDThroughAModule(t *testing.T) {
	h := startHost(t, "rocky10")
	h.exec("Welcome\n", "sh", "-c", "cat > /etc/motd && chmod 0644 /etc/motd")

	w := newWorkdir(t, "import_module")
	w.writeAs("main.tf", importModuleVars{h.port, h.keyFile, h.knownHosts})
	site := filepath.Join(w.dir, "site")
	if err := os.Mkdir(site, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(site, "main.circuit.hcl"), []byte(`variable "hosts" {
  type = map(string)
}

variable "ssh" {
  type = object({
    port             = number
    user             = string
    private_key_file = string
    known_hosts_file = string
  })
}

circuit "site" {
  hosts = var.hosts
  ssh {
    port             = var.ssh.port
    user             = var.ssh.user
    private_key_file = var.ssh.private_key_file
    known_hosts_file = var.ssh.known_hosts_file
  }

  step "motd" {
    file {
      path    = "/etc/motd"
      content = "Welcome\n"
      mode    = "0644"
    }
  }
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	w.mustConn3x("init", "-no-color")
	out := w.mustConn3x("plan", "-no-color")
	t.Logf("first plan:\n%s", out)
	if !strings.Contains(out, "Plan: 1 to import, 0 to add, 0 to change, 0 to destroy.") {
		t.Fatalf("the plan should import the step and change nothing:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("the plan after import isn't empty:\n%s", out)
	}
}
