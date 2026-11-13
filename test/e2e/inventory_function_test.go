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

// A circuit takes its hosts from an Ansible inventory, with each host's
// address and port from ansible_host and ansible_port, and its variables,
// group ones included, in each.value.vars.
func TestInventoryFunction(t *testing.T) {
	web1, web2 := startHost(t, "rocky10"), startHost(t, "rocky10")
	knownFile := shareKey(t, web1, web2)
	w := newWorkdir(t, "inventory_function")
	w.writeAs("main.circuit.hcl", chainVars{Key: web1.keyFile, KnownHosts: knownFile})
	inv := "[web]\nweb1 ansible_host=127.0.0.1 ansible_port=" + web1.port + "\nweb2 ansible_host=127.0.0.1 ansible_port=" + web2.port + " role=db\n\n[web:vars]\nrole=app\n"
	// Provider functions need their provider in required_providers, as in
	// OpenTofu; conn3x is built in.
	versions := "terraform {\n  required_providers {\n    conn3x = { source = \"terraform.io/builtin/conn3x\" }\n  }\n}\n"
	for name, content := range map[string]string{"inventory.ini": inv, "versions.tf": versions} {
		if err := os.WriteFile(filepath.Join(w.dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	for h, want := range map[*host]string{web1: "app", web2: "db"} {
		if got := strings.TrimSpace(h.exec("", "cat", "/tmp/role")); got != want {
			t.Errorf("/tmp/role = %q, want %q", got, want)
		}
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes") {
		t.Errorf("a second plan should have nothing to do:\n%s", out)
	}
}
