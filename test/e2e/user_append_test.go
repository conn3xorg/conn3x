// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type userAppendVars struct {
	Port, KeyFile, KnownHosts, Groups string
	Append                            bool
}

// With append, a user step adds a group and leaves the others the user is
// in, and a group taken away by hand plans a change.
func TestUserAppendGroups(t *testing.T) {
	h := startHost(t, "debian13")
	groups := func() string { return strings.TrimSpace(h.exec("", "id", "-nG", "conn3xapp")) }
	w := newWorkdir(t, "user-append")
	w.writeAs("main.circuit.hcl", userAppendVars{h.port, h.keyFile, h.knownHosts, `"conn3xa"`, false})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")

	w.writeAs("main.circuit.hcl", userAppendVars{h.port, h.keyFile, h.knownHosts, `"conn3xb"`, true})
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := groups(); !strings.Contains(got, "conn3xa") || !strings.Contains(got, "conn3xb") {
		t.Fatalf("after the append apply: %s", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}

	h.exec("", "gpasswd", "-d", "conn3xapp", "conn3xb")
	if out := w.mustConn3x("plan", "-no-color"); strings.Contains(out, "No changes.") {
		t.Fatalf("a group taken away plans nothing:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := groups(); !strings.Contains(got, "conn3xa") || !strings.Contains(got, "conn3xb") {
		t.Fatalf("after putting it back: %s", got)
	}
}
