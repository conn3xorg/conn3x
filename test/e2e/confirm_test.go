// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type confirmVars struct {
	Port, KeyFile, KnownHosts string
	Content                   string
}

// confirm_after on a file step: an sshd change that refuses root, the login
// Conn3x uses, is put back by the host itself when the confirm can't log in,
// and root can log in again; a harmless change confirms and leaves no timer
// or copy behind.
func TestConfirmAfterRevertsALockout(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "confirm")
	vars := confirmVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Content: `PermitRootLogin no\n`}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")

	// The drop-in starts as a link. Writing replaces the link, not the file
	// it points to, so the revert has to put the link back as it was.
	h.exec("", "sh", "-c", "printf '# kept\\n' > /root/kept.conf && ln -s /root/kept.conf /etc/ssh/sshd_config.d/99-conn3x.conf")

	out, code := w.conn3x("apply", "-auto-approve", "-no-color")
	t.Logf("apply of the lockout:\n%s", out)
	if code == 0 || !strings.Contains(out, "the host put the old state back by itself; it answers again now") {
		t.Fatalf("the lockout should fail and be reverted by the host (exit %d):\n%s", code, out)
	}
	if got := h.exec("", "sh", "-c", "readlink /etc/ssh/sshd_config.d/99-conn3x.conf; cat /root/kept.conf"); got != "/root/kept.conf\n# kept\n" {
		t.Errorf("after the revert, the drop-in's link and what it points to = %q", got)
	}
	// Conn3x can log in again: a plan reads the host.
	if out, code := w.conn3x("plan", "-no-color"); code != 0 {
		t.Fatalf("can't plan after the revert (exit %d):\n%s", code, out)
	}

	vars.Content = `# harmless\n`
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", "/etc/ssh/sshd_config.d/99-conn3x.conf"); got != "# harmless\n" {
		t.Errorf("the confirmed drop-in = %q", got)
	}
	if got := strings.TrimSpace(h.exec("", "sh", "-c", "systemctl list-timers --all --no-legend 'conn3x-revert-*' | wc -l; ls -A /var/lib/conn3x/revert | wc -l; stat -c %a /var/lib/conn3x/revert")); got != "0\n0\n700" {
		t.Errorf("after a confirm, timers, copies and the directory's mode = %q", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after the confirmed apply:\n%s", out)
	}
}
