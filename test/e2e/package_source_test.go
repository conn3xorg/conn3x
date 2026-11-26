// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os/exec"
	"strings"
	"testing"
)

type packageSourceVars struct {
	Port, KeyFile, KnownHosts string
	Ext, Version, OnRemove    string
	SourceSHA256              string
	WithFile, WithPackage     bool
}

// buildDeb and buildRPM make conn3x-demo 1.0 and 2.0 in /opt/builds, each
// a package with one file that says its version, and 2.0b, another 2.0
// whose file says 2.0b.
const buildDeb = `set -e
mkdir -p /opt/builds
for v in 1.0 2.0 2.0b; do
  d=$(mktemp -d)
  mkdir -p "$d/DEBIAN" "$d/usr/share/conn3x-demo"
  printf 'Package: conn3x-demo\nVersion: %s-1\nArchitecture: all\nMaintainer: Conn3x <e2e@example.com>\nDescription: e2e test package\n' "${v%b}" > "$d/DEBIAN/control"
  echo "$v" > "$d/usr/share/conn3x-demo/version"
  dpkg-deb --build --root-owner-group "$d" "/opt/builds/conn3x-demo-$v.deb" >/dev/null
done`

const buildRPM = `set -e
dnf -y -q install rpm-build >/dev/null
mkdir -p /opt/builds
for v in 1.0 2.0 2.0b; do
  cat > /root/demo.spec <<EOF
Name: conn3x-demo
Version: ${v%b}
Release: 1
Summary: e2e test package
License: MPL-2.0
BuildArch: noarch
%description
e2e test package
%install
mkdir -p %{buildroot}/usr/share/conn3x-demo
echo $v > %{buildroot}/usr/share/conn3x-demo/version
%files
/usr/share/conn3x-demo/version
EOF
  rpmbuild -bb --quiet --define '_topdir /root/rpmbuild' /root/demo.spec >/dev/null
  cp "/root/rpmbuild/RPMS/noarch/conn3x-demo-${v%b}-1.noarch.rpm" "/opt/builds/conn3x-demo-$v.rpm"
done`

// A package step with source installs a .deb or .rpm that an earlier
// step puts in place in the same apply, plans clean, sees a newer file
// once it's on the host, downgrades to an older one that an earlier step
// swaps in during an apply planned for another reason, and is removed by
// name (#1350). With source_sha256, the plan that brings a newer file
// installs it in the same apply, a file with another hash is refused,
// and one swapped on the host shows as a change (#1416).
func TestPackageSource(t *testing.T) {
	for _, image := range []string{"ubuntu2404", "rocky10", "leap156"} {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			vars := packageSourceVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Ext: "deb", Version: "1.0", OnRemove: "forget", WithFile: true, WithPackage: true}
			build := buildDeb
			switch {
			case rpmImage(image):
				vars.Ext, build = "rpm", buildRPM
			case image == "leap156":
				vars.Ext, build = "rpm", strings.Replace(buildRPM, "dnf -y -q install", "zypper -n -q install", 1)
			}
			h.exec("", "sh", "-c", build)
			installed := func() string {
				t.Helper()
				return h.exec("", "cat", "/usr/share/conn3x-demo/version")
			}
			sum := func(v string) string {
				t.Helper()
				return strings.Fields(h.exec("", "sha256sum", "/opt/builds/conn3x-demo-"+v+"."+vars.Ext))[0]
			}

			w := newWorkdir(t, "package_source")
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")

			// The file isn't there at plan: the step before makes it.
			out := w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, `conn3x_package.agent__agent["box"] will be created`) {
				t.Fatalf("plan before the file exists:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := installed(); got != "1.0\n" {
				t.Fatalf("after the first apply: %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after install:\n%s", out)
			}

			// A newer file shows once it's on the host.
			vars.Version = "2.0"
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			out = w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, `conn3x_package.agent__agent["box"] will be updated`) || !strings.Contains(out, "source_version") || !strings.Contains(out, "1 to change") {
				t.Fatalf("plan with the newer file on the host:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := installed(); got != "2.0\n" {
				t.Fatalf("after the upgrade: %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after the upgrade:\n%s", out)
			}

			// An apply planned only for on_remove reads the file again, which
			// the step before has swapped for the older one: it downgrades,
			// with no "inconsistent result" (#1376).
			vars.Version, vars.OnRemove = "1.0", "delete"
			w.writeAs("main.circuit.hcl", vars)
			if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code != 0 {
				t.Fatalf("apply with the older file swapped in exited %d:\n%s", code, out)
			}
			if got := installed(); got != "1.0\n" {
				t.Fatalf("after the downgrade: %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after the downgrade:\n%s", out)
			}

			// With source_sha256 changed along with the file, as a download's
			// url and sha256 would be, one plan shows the upgrade and one
			// apply makes it.
			vars.SourceSHA256 = sum("1.0")
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			vars.Version, vars.SourceSHA256 = "2.0", sum("2.0")
			w.writeAs("main.circuit.hcl", vars)
			out = w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, `conn3x_package.agent__agent["box"] will be updated`) || !strings.Contains(out, "2 to change") {
				t.Fatalf("plan with a new source_sha256:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := installed(); got != "2.0\n" {
				t.Fatalf("after one apply with a new source_sha256: %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after the upgrade with source_sha256:\n%s", out)
			}

			// A file with another hash than source_sha256 isn't installed.
			vars.Version, vars.SourceSHA256 = "2.0b", sum("1.0")
			w.writeAs("main.circuit.hcl", vars)
			if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code == 0 || !strings.Contains(out, "refusing to install it") {
				t.Fatalf("apply with the wrong file exited %d:\n%s", code, out)
			}
			if got := installed(); got != "2.0\n" {
				t.Fatalf("after refusing the wrong file: %q", got)
			}

			// A file swapped on the host for another 2.0 shows as a change
			// to the package as well as the file, and the apply puts both
			// back.
			vars.Version, vars.SourceSHA256 = "2.0", sum("2.0")
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			h.exec("", "cp", "/opt/builds/conn3x-demo-2.0b."+vars.Ext, "/opt/downloads/conn3x-demo."+vars.Ext)
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, `conn3x_package.agent__agent["box"] will be updated`) || !strings.Contains(out, "source_sha256") {
				t.Fatalf("plan with the file swapped:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after putting the file back:\n%s", out)
			}

			// A file that's gone, as from /tmp after a reboot, leaves the
			// package as it is: an apply planned for on_remove succeeds,
			// both ways, and the package stays, source_sha256 or not.
			vars.WithFile = false
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			h.exec("", "rm", "/opt/downloads/conn3x-demo."+vars.Ext)
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan with the file gone:\n%s", out)
			}
			for _, onRemove := range []string{"forget", "delete"} {
				vars.OnRemove = onRemove
				w.writeAs("main.circuit.hcl", vars)
				if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code != 0 {
					t.Fatalf("apply for on_remove = %q with the file gone exited %d:\n%s", onRemove, code, out)
				}
				if got := installed(); got != "2.0\n" {
					t.Fatalf("after on_remove = %q with the file gone: %q", onRemove, got)
				}
				if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
					t.Fatalf("plan after on_remove = %q with the file gone:\n%s", onRemove, out)
				}
			}

			// Removing the step removes the package by name.
			vars.WithPackage = false
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			query := "dpkg -s conn3x-demo"
			if vars.Ext == "rpm" {
				query = "rpm -q conn3x-demo"
			}
			if err := exec.Command("podman", "exec", h.container, "sh", "-c", query).Run(); err == nil {
				t.Fatal("conn3x-demo still installed after removing the step with on_remove = delete")
			}
		})
	}
}
