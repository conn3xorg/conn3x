// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type packageRepoReleaseVars struct {
	Port, KeyFile, KnownHosts string
	Name, From                string
}

// enable_repositories installs nasm from Rocky's CRB, which stays off,
// and target_release installs tmux from trixie-backports, whose 3.7c is
// newer than trixie's 3.5a: with state "latest", a plan that read the
// candidate without -t would want trixie's and never be clean. The
// argument for the other family fails, naming the host (#1351).
func TestPackageRepoRelease(t *testing.T) {
	for _, c := range []struct {
		image, name, from, wrong, check, want string
	}{
		{"rocky10", "nasm", `enable_repositories = ["crb"]`, `target_release = "trixie-backports"`,
			"rpm -q nasm && dnf -q repolist --disabled crb", "crb"},
		{"debian13", "tmux", `target_release = "trixie-backports"`, `enable_repositories = ["crb"]`,
			"dpkg-query -W -f '${Version}' tmux", "~bpo13"},
	} {
		t.Run(c.image, func(t *testing.T) {
			h := startHost(t, c.image)
			if c.image == "debian13" {
				// The image has no backports, and no package lists yet: the
				// install fetches them once -t finds the release missing.
				h.exec("Types: deb\nURIs: http://deb.debian.org/debian\nSuites: trixie-backports\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.pgp\n",
					"sh", "-c", "cat > /etc/apt/sources.list.d/backports.sources")
			}
			vars := packageRepoReleaseVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Name: c.name, From: c.wrong}
			w := newWorkdir(t, "package_repo_release")
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")
			out, code := w.conn3x("apply", "-auto-approve", "-no-color")
			if code == 0 || !strings.Contains(out, "on 127.0.0.1") || !strings.Contains(out, "only applies on") {
				t.Fatalf("apply with the other family's argument exited %d:\n%s", code, out)
			}

			vars.From = c.from
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			got := h.exec("", "sh", "-c", c.check)
			t.Logf("%s: %s", c.check, got)
			if !strings.Contains(got, c.want) {
				t.Fatalf("after apply: %q, want %q", got, c.want)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after install:\n%s", out)
			}
		})
	}
}
