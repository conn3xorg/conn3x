// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// A sudoers step writes a rule sudo takes, mode 0440, and removes it.
func TestSudoersStep(t *testing.T) {
	box := startHost(t, "rocky10")
	knownFile := shareKey(t, box)
	w := newWorkdir(t, "sudoers")
	w.writeAs("main.circuit.hcl", chainVars{PortA: box.port, Key: box.keyFile, KnownHosts: knownFile})
	w.mustConn3x("init", "-no-color")
	rules := func() string { return box.exec("", "sh", "-c", "sudo -l -U nobody 2>&1 || true") }

	w.mustConn3x("apply", "-auto-approve", "-no-color", `-var=commands=["/usr/bin/id", "/usr/bin/systemctl restart sshd"]`)
	if got := rules(); !strings.Contains(got, "(ALL) NOPASSWD: /usr/bin/id, /usr/bin/systemctl restart sshd") {
		t.Errorf("sudo -l -U nobody:\n%s", got)
	}
	if mode := strings.TrimSpace(box.exec("", "stat", "-c", "%a %U", "/etc/sudoers.d/conn3x-test")); mode != "440 root" {
		t.Errorf("mode = %q", mode)
	}
	if out := w.mustConn3x("plan", "-no-color", `-var=commands=["/usr/bin/id", "/usr/bin/systemctl restart sshd"]`); !strings.Contains(out, "No changes") {
		t.Errorf("a second plan should be clean:\n%s", out)
	}

	w.mustConn3x("apply", "-auto-approve", "-no-color", `-var=commands=["/usr/bin/id"]`, "-var=present=false")
	if got := rules(); strings.Contains(got, "/usr/bin/id") {
		t.Errorf("on_remove = delete should remove the rule:\n%s", got)
	}
}
