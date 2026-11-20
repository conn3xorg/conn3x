// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os/exec"
	"strings"
	"testing"
)

// A source binds a network to a zone, running and permanent. One already
// bound to another zone fails the step, naming that zone, rather than
// being moved. Removing the step unbinds it from both.
func TestFirewalldSource(t *testing.T) {
	h := startHostWith(t, "rocky10", "--privileged")
	w := newWorkdir(t, "firewalld_source")
	vars := firewalldRichVars{h.port, h.keyFile, h.knownHosts, false}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	h.exec("", "systemctl", "enable", "--now", "firewalld")
	sources := func(perm string) string {
		args := []string{"firewall-cmd", "--zone=trusted", "--list-sources"}
		if perm != "" {
			args = append(args, perm)
		}
		return strings.TrimSpace(h.exec("", args...))
	}

	h.exec("", "firewall-cmd", "--zone=public", "--add-source=10.42.0.0/16")
	vars.Rule = true
	w.writeAs("main.circuit.hcl", vars)
	out, code := w.conn3x("apply", "-auto-approve", "-no-color")
	if code == 0 || !strings.Contains(out, "already bound to zone public") {
		t.Fatalf("a source in another zone: exit %d:\n%s", code, out)
	}
	if err := exec.Command("podman", "exec", h.container, "firewall-cmd", "--zone=public", "--remove-source=10.42.0.0/16").Run(); err != nil {
		t.Fatal(err)
	}

	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got, perm := sources(""), sources("--permanent"); got != "10.42.0.0/16" || perm != "10.42.0.0/16" {
		t.Fatalf("after binding: running %q, permanent %q", got, perm)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after binding:\n%s", out)
	}

	vars.Rule = false
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got, perm := sources(""), sources("--permanent"); got != "" || perm != "" {
		t.Fatalf("after removing the step: running %q, permanent %q", got, perm)
	}
}
