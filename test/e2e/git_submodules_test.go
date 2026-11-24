// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// A git step with submodules checks them out, nested ones too, sees one
// moved by hand and puts it back; without submodules the directory stays
// empty and plans clean (#1348).
func TestGitSubmodules(t *testing.T) {
	h := startHost(t, "ubuntu2404")
	h.exec("", "sh", "-c", "apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq -y install git >/dev/null")
	// git refuses file:// submodules by default (CVE-2022-39253); these are
	// the test's own repositories.
	h.exec("", "sh", "-c", `set -e
git config --system protocol.file.allow always
c="git -c user.name=t -c user.email=t@example.com"
mkdir -p /srv/repos && cd /srv/repos
git init -q -b main inner && echo in > inner/f && git -C inner add f && $c -C inner commit -qm in
git init -q -b main lib && echo lib > lib/f && git -C lib add f
$c -C lib submodule --quiet add file:///srv/repos/inner inner && $c -C lib commit -qm lib
git init -q -b main app && $c -C app submodule --quiet add file:///srv/repos/lib lib && $c -C app commit -qm app`)

	w := newWorkdir(t, "git_submodules")
	w.writeAs("main.circuit.hcl", fetchVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")

	if got := h.exec("", "cat", "/srv/with/lib/f", "/srv/with/lib/inner/f"); got != "lib\nin\n" {
		t.Fatalf("submodule files = %q", got)
	}
	if got := strings.TrimSpace(h.exec("", "sh", "-c", "ls -A /srv/without/lib | wc -l")); got != "0" {
		t.Fatalf("submodules = false left %s entries in /srv/without/lib", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}

	// Someone moves the submodule to another commit by hand.
	h.exec("", "sh", "-c", `set -e
c="git -c user.name=t -c user.email=t@example.com"
echo moved > /srv/repos/lib/f && $c -C /srv/repos/lib commit -qam moved
git -C /srv/with/lib fetch -q origin main && git -C /srv/with/lib checkout -q FETCH_HEAD`)
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, `subs__with["box"] will be updated`) || !strings.Contains(out, "1 to change") {
		t.Fatalf("plan after moving the submodule:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", "/srv/with/lib/f"); got != "lib\n" {
		t.Fatalf("lib/f after apply = %q", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after restoring:\n%s", out)
	}
}
