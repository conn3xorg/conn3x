// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type ufwLoggingVars struct{ Port, KeyFile, KnownHosts, Logging string }

// ufw_settings sets ufw's logging level, and reads it back from LOGLEVEL
// in /etc/ufw/ufw.conf, which ufw writes whether or not it's on. on
// matches any level but off, since ufw logging on keeps the level it has.
func TestUFWSettingsLogging(t *testing.T) {
	h := startHost(t, "ubuntu2404")
	w := newWorkdir(t, "ufw_logging")
	vars := ufwLoggingVars{h.port, h.keyFile, h.knownHosts, "medium"}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	loglevel := func() string { return strings.TrimSpace(h.exec("", "grep", "^LOGLEVEL=", "/etc/ufw/ufw.conf")) }
	if got := loglevel(); got != "LOGLEVEL=medium" {
		t.Fatalf("after apply: %s", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}

	h.exec("", "ufw", "logging", "high")
	if out := w.mustConn3x("plan", "-no-color"); strings.Contains(out, "No changes.") {
		t.Fatalf("a hand change plans nothing:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := loglevel(); got != "LOGLEVEL=medium" {
		t.Fatalf("after putting it back: %s", got)
	}

	vars.Logging = "on"
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := loglevel(); got != "LOGLEVEL=medium" {
		t.Fatalf("on changed the level: %s", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("on plans a change while logging at medium:\n%s", out)
	}
	h.exec("", "ufw", "logging", "off")
	if out := w.mustConn3x("plan", "-no-color"); strings.Contains(out, "No changes.") {
		t.Fatalf("logging off plans nothing against on:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := loglevel(); got != "LOGLEVEL=low" {
		t.Fatalf("on from off: %s", got)
	}
}
