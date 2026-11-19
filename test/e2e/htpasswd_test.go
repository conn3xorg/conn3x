// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type htpasswdVars struct{ Port, KeyFile, KnownHosts, Password string }

// TestHtpasswd writes a user's line that Apache's own htpasswd -v accepts,
// plans clean, changes the password, leaves another user's line alone, and
// takes its line out when the step goes.
func TestHtpasswd(t *testing.T) {
	h := startHost(t, "debian13")
	h.exec("", "sh", "-c", "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq apache2-utils >/dev/null")
	verify := func(pw string) bool {
		return strings.TrimSpace(h.exec("", "sh", "-c", `htpasswd -vb /etc/conn3x-htpasswd admin "$1" >/dev/null 2>&1 && echo ok || echo no`, "sh", pw)) == "ok"
	}
	w := newWorkdir(t, "htpasswd")
	w.writeAs("main.circuit.hcl", htpasswdVars{h.port, h.keyFile, h.knownHosts, "first 'pw'"})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if !verify("first 'pw'") || verify("wrong") {
		t.Fatalf("htpasswd -v doesn't take the password:\n%s", h.exec("", "cat", "/etc/conn3x-htpasswd"))
	}
	if got := strings.TrimSpace(h.exec("", "stat", "-c", "%a", "/etc/conn3x-htpasswd")); got != "640" {
		t.Fatalf("mode %s", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}
	if out, _ := w.conn3x("show", "-no-color"); strings.Contains(out, "first") {
		t.Fatalf("the password reached state:\n%s", out)
	}

	h.exec("", "sh", "-c", "echo 'other:$apr1$abc$def' >> /etc/conn3x-htpasswd")
	w.writeAs("main.circuit.hcl", htpasswdVars{h.port, h.keyFile, h.knownHosts, "second"})
	if out := w.mustConn3x("plan", "-no-color"); strings.Contains(out, "No changes.") {
		t.Fatalf("a new password plans nothing:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if !verify("second") || verify("first 'pw'") {
		t.Fatal("the new password didn't take")
	}
	if !strings.Contains(h.exec("", "cat", "/etc/conn3x-htpasswd"), "other:$apr1$abc$def") {
		t.Fatal("another user's line changed")
	}

	w.mustConn3x("destroy", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", "/etc/conn3x-htpasswd"); got != "other:$apr1$abc$def\n" {
		t.Fatalf("after destroy: %q", got)
	}
}
