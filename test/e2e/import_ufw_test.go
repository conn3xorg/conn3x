// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type importUFWVars struct {
	Port, KeyFile, KnownHosts string
	Missing                   bool
}

// ufw rules added by hand are adopted with nothing to change, the next
// plan is empty, and a rule the host doesn't have fails the plan instead
// of being added. ufw keeps rules whether or not it is enabled, so this
// runs in a container, as ufw_test.go does.
func TestStepImportUFWRules(t *testing.T) {
	h := startHost(t, "ubuntu2404")
	h.exec("", "sh", "-c", "DEBIAN_FRONTEND=noninteractive apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y ufw")
	h.exec("", "ufw", "allow", "22/tcp")
	h.exec("", "ufw", "deny", "from", "10.0.0.0/8", "to", "any", "port", "6000:6007", "proto", "tcp")

	w := newWorkdir(t, "import_ufw")
	vars := importUFWVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")
	out := w.mustConn3x("plan", "-no-color")
	t.Logf("first plan:\n%s", out)
	if !strings.Contains(out, "Plan: 2 to import, 0 to add, 0 to change, 0 to destroy.") {
		t.Fatalf("the first plan should import both rules and change nothing:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("the plan after import isn't empty:\n%s", out)
	}

	vars.Missing = true
	w.writeAs("main.circuit.hcl", vars)
	out, code := w.conn3x("plan", "-no-color")
	t.Logf("plan with a missing rule:\n%s", out)
	if code == 0 || !strings.Contains(out, "Nothing to import on box") || !strings.Contains(out, "the ufw rule allow 8080/tcp on box") {
		t.Fatalf("importing a rule the host doesn't have should fail the plan (exit %d):\n%s", code, out)
	}
}
