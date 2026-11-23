// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type alpineVars struct{ Port, KeyFile, KnownHosts, State, Version string }

// package on Alpine installs with apk, plans clean, holds a pinned version,
// and removes the package.
func TestPackageAlpine(t *testing.T) {
	h := startHost(t, "alpine322")
	installed := func() string { return h.exec("", "sh", "-c", "apk list -I tree; true") }
	w := newWorkdir(t, "package_alpine")
	vars := alpineVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, State: "present"}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	got := installed()
	if !strings.Contains(got, "[installed]") {
		t.Fatalf("after apply: %q", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}

	// The installed version, without its -rN, as a pin, with tree removed
	// first so the apply installs it that way.
	version := strings.TrimPrefix(strings.Fields(got)[0], "tree-")
	vars.Version = version[:strings.LastIndex(version, "-r")]
	h.exec("", "apk", "del", "-q", "tree")
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := installed(); !strings.Contains(got, "[installed]") {
		t.Fatalf("after installing with version %s: %q", vars.Version, got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan with version %s:\n%s", vars.Version, out)
	}

	vars.State, vars.Version = "latest", ""
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan with state latest:\n%s", out)
	}

	vars.State = "absent"
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := strings.TrimSpace(installed()); got != "" {
		t.Fatalf("after state absent: %q", got)
	}
}
