// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// debRepo and rpmRepo put conn3x-demo 1.0 and 2.0, from buildDeb and
// buildRPM, in a local repository. The distro archives carry two
// versions of a package only now and then, so the test brings its own.
const debRepo = `set -e
mkdir -p /opt/repo
cd /opt/repo
for v in 1.0 2.0; do
  f=conn3x-demo-$v.deb
  cp "/opt/builds/$f" .
  dpkg-deb -f "$f"
  printf 'Filename: ./%s\nSize: %s\nSHA256: %s\n\n' "$f" "$(stat -c %s "$f")" "$(sha256sum "$f" | cut -d' ' -f1)"
done > Packages
echo 'deb [trusted=yes] file:/opt/repo ./' > /etc/apt/sources.list.d/conn3x-demo.list
apt-get update -q -o Dir::Etc::sourcelist=sources.list.d/conn3x-demo.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 >/dev/null`

const rpmRepo = `set -e
dnf -y -q install createrepo_c >/dev/null
mkdir -p /opt/repo
cp /opt/builds/conn3x-demo-1.0.rpm /opt/builds/conn3x-demo-2.0.rpm /opt/repo/
createrepo_c -q /opt/repo
printf '[conn3x-demo]\nname=conn3x-demo\nbaseurl=file:///opt/repo\ngpgcheck=0\n' > /etc/yum.repos.d/conn3x-demo.repo`

// A package step's version is the version the host ends up with: a pin
// below the installed version downgrades the package from the
// repository, and the next plan is clean (#1476). apt needs
// --allow-downgrades for it; dnf's install does it as it is.
func TestPackageDowngrade(t *testing.T) {
	for _, image := range []string{"debian13", "rocky10"} {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			if rpmImage(image) {
				h.exec("", "sh", "-c", buildRPM+"\n"+rpmRepo)
			} else {
				h.exec("", "sh", "-c", buildDeb+"\n"+debRepo)
			}
			vars := struct{ Port, KeyFile, KnownHosts, Version string }{h.port, h.keyFile, h.knownHosts, "2.0-1"}
			w := newWorkdir(t, "package_downgrade")
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")
			for _, v := range []string{"2.0", "1.0"} {
				vars.Version = v + "-1"
				w.writeAs("main.circuit.hcl", vars)
				if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code != 0 {
					t.Fatalf("apply with version %s exited %d:\n%s", vars.Version, code, out)
				}
				if got := h.exec("", "cat", "/usr/share/conn3x-demo/version"); got != v+"\n" {
					t.Fatalf("after apply with version %s: %q", vars.Version, got)
				}
				if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
					t.Fatalf("plan after apply with version %s:\n%s", vars.Version, out)
				}
			}
		})
	}
}
