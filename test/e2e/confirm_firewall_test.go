// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type confirmFirewallVars struct {
	Port, KeyFile, KnownHosts string
	Tool                      string
	Rule                      bool
}

// confirm_after on a ufw rule: removing the rule that lets SSH in locks
// Conn3x out, and the host adds it back by itself. --privileged lets the
// container run a real firewall.
func TestConfirmAfterUndoesAUFWLockout(t *testing.T) {
	h := startHostWith(t, "debian13", "--privileged")
	w := newWorkdir(t, "confirm_firewall")
	vars := confirmFirewallVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Tool: "ufw", Rule: true}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")

	// The published port reaches sshd over the container's loopback, which
	// ufw always lets in. Without that line, the login meets the rules as a
	// login from another machine would.
	h.exec("", "sed", "-i", "/-A ufw-before-input -i lo -j ACCEPT/d", "/etc/ufw/before.rules")
	h.exec("", "ufw", "--force", "enable")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan with ufw up:\n%s", out)
	}

	vars.Rule = false
	w.writeAs("main.circuit.hcl", vars)
	out, code := w.conn3x("apply", "-auto-approve", "-no-color")
	t.Logf("apply of the lockout:\n%s", out)
	if code == 0 || !strings.Contains(out, "the host put the old state back by itself; it answers again now") {
		t.Fatalf("removing the SSH rule should fail and be undone by the host (exit %d):\n%s", code, out)
	}
	if got := h.exec("", "ufw", "show", "added"); !strings.Contains(got, "ufw allow 22/tcp\n") {
		t.Errorf("the SSH rule wasn't put back:\n%s", got)
	}
	if got := strings.TrimSpace(h.exec("", "sh", "-c", "systemctl list-timers --all --no-legend 'conn3x-revert-*' | wc -l; ls -A /var/lib/conn3x/revert | wc -l")); got != "0\n0" {
		t.Errorf("after the undo, timers and copies = %q", got)
	}
	if out, code := w.conn3x("plan", "-no-color"); code != 0 {
		t.Fatalf("can't plan after the undo (exit %d):\n%s", code, out)
	}
}

// confirm_after on a firewalld rule that doesn't lock Conn3x out: the
// change is confirmed over a new login and leaves nothing behind. firewalld
// always lets the container's loopback in, so a lockout can't be shown
// here; the ufw test above shows the host's undo.
func TestConfirmAfterFirewalld(t *testing.T) {
	h := startHostWith(t, "rocky10", "--privileged")
	w := newWorkdir(t, "confirm_firewall")
	vars := confirmFirewallVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Tool: "firewalld"}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	h.exec("", "systemctl", "enable", "--now", "firewalld")

	vars.Rule = true
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	vars.Rule = false
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")

	if got := h.exec("", "sh", "-c", "firewall-cmd --list-services; firewall-cmd --permanent --list-services"); strings.Contains(got, "ssh") {
		t.Errorf("the removed rule is still there:\n%s", got)
	}
	if got := strings.TrimSpace(h.exec("", "sh", "-c", "journalctl -q -u 'conn3x-revert-*.timer' | grep -c Started; systemctl list-timers --all --no-legend 'conn3x-revert-*' | wc -l; ls -A /var/lib/conn3x/revert | wc -l")); got != "1\n0\n0" {
		t.Errorf("guards armed, timers and copies left = %q", got)
	}
}
