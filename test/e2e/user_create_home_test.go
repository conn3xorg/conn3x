// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type userCreateHomeVars struct {
	Port, KeyFile, KnownHosts string
	CreateHome                bool
}

// create_home = false creates a service account without a home directory,
// and turning it on later changes nothing on the host, since it only
// matters when the user is created.
func TestUserCreateHome(t *testing.T) {
	h := startHost(t, "debian13")
	hasHome := func() bool {
		return strings.TrimSpace(h.exec("", "sh", "-c", "test -e /home/conn3xsvc && echo yes || echo no")) == "yes"
	}
	w := newWorkdir(t, "user-create-home")
	w.writeAs("main.circuit.hcl", userCreateHomeVars{h.port, h.keyFile, h.knownHosts, false})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := strings.TrimSpace(h.exec("", "getent", "passwd", "conn3xsvc")); got == "" {
		t.Fatal("the user wasn't created")
	}
	if hasHome() {
		t.Fatal("create_home = false made /home/conn3xsvc")
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}

	w.writeAs("main.circuit.hcl", userCreateHomeVars{h.port, h.keyFile, h.knownHosts, true})
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if hasHome() {
		t.Fatal("turning create_home on for an existing user made a home directory")
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after turning it on:\n%s", out)
	}
}
