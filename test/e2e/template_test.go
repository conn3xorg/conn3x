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

type templateVars struct{ Port, KeyFile, KnownHosts, Owner string }

func TestTemplateStep(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "template")
	tpl := "Welcome to ${host}.\n%{ if owner != \"\" }Managed by ${owner}.\n%{ endif }"
	if err := os.WriteFile(filepath.Join(w.dir, "motd.tftpl"), []byte(tpl), 0o644); err != nil {
		t.Fatal(err)
	}
	w.writeAs("main.circuit.hcl", templateVars{h.port, h.keyFile, h.knownHosts, "the platform team"})
	w.mustConn3x("init", "-no-color")
	out := w.mustConn3x("plan", "-no-color")
	if !strings.Contains(out, "Welcome to web1.") || !strings.Contains(out, "Managed by the platform team.") {
		t.Fatalf("plan does not show the rendered template:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", "/etc/motd"); got != "Welcome to web1.\nManaged by the platform team.\n" {
		t.Fatalf("/etc/motd = %q", got)
	}

	// Changing a variable changes the rendered file.
	w.writeAs("main.circuit.hcl", templateVars{h.port, h.keyFile, h.knownHosts, "ops"})
	out = w.mustConn3x("plan", "-no-color")
	if !strings.Contains(out, "- Managed by the platform team.") || !strings.Contains(out, "+ Managed by ops.") {
		t.Fatalf("variable change plan:\n%s", out)
	}
}
