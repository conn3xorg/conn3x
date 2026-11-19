// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type ufwSettingsVars struct {
	Port, KeyFile, KnownHosts, From string
	AllowSSH                        bool
}

// ufw_settings turns ufw on with incoming denied, but only once a rule lets
// sshd's port in. --privileged lets the container run a real firewall.
func TestUFWSettings(t *testing.T) {
	h := startHostWith(t, "debian13", "--privileged")
	w := newWorkdir(t, "ufw_settings")
	vars := ufwSettingsVars{h.port, h.keyFile, h.knownHosts, "", false}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")

	out, code := w.conn3x("apply", "-auto-approve", "-no-color")
	if code == 0 || !strings.Contains(out, "no ufw rule lets this connection in") {
		t.Fatalf("enabling without an SSH rule: exit %d:\n%s", code, out)
	}
	if got := h.exec("", "ufw", "status"); !strings.Contains(got, "inactive") {
		t.Fatalf("ufw changed anyway: %s", got)
	}

	// A rule only from a network Conn3x isn't on counts here, because
	// this login arrives over loopback, which ufw always lets in. That it
	// counts shows the step read where the login comes from.
	vars.AllowSSH, vars.From = true, "203.0.113.0/24"
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	got := h.exec("", "ufw", "status", "verbose")
	if !strings.Contains(got, "Status: active") || !strings.Contains(got, "deny (incoming), allow (outgoing)") {
		t.Fatalf("after enabling:\n%s", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after enabling:\n%s", out)
	}

	h.exec("", "ufw", "default", "allow", "incoming")
	if out := w.mustConn3x("plan", "-no-color"); strings.Contains(out, "No changes.") {
		t.Fatalf("a hand change plans nothing:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "ufw", "status", "verbose"); !strings.Contains(got, "deny (incoming)") {
		t.Fatalf("after putting it back:\n%s", got)
	}
}
