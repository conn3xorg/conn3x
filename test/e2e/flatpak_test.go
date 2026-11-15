// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type flatpakVars struct{ Port, KeyFile, KnownHosts, State string }

// flatpakRepo builds a one-app Flatpak repository on the host and adds it as
// the remote "local". Flathub's smallest app pulls a runtime of hundreds of
// megabytes, so the test ships its own runtime: an empty one, and an app
// whose only file is a script that prints greeting.
const flatpakRepo = `set -e
arch=$(flatpak --default-arch)
mkdir -p /srv/fp/rt/files /srv/fp/rt/usr /srv/fp/app/files/bin /srv/fp/app/export
printf '[Runtime]\nname=org.test.Platform\nruntime=org.test.Platform/%s/stable\n' "$arch" > /srv/fp/rt/metadata
printf '[Application]\nname=org.test.Hello\nruntime=org.test.Platform/%s/stable\ncommand=hello\n' "$arch" > /srv/fp/app/metadata
printf '#!/bin/sh\necho %s\n' "$1" > /srv/fp/app/files/bin/hello
chmod +x /srv/fp/app/files/bin/hello
flatpak build-export --runtime /srv/fp/repo /srv/fp/rt stable >/dev/null
flatpak build-export /srv/fp/repo /srv/fp/app stable >/dev/null
flatpak remote-add --if-not-exists --no-gpg-verify local file:///srv/fp/repo
`

// TestFlatpak installs an app from a remote, keeps it at the remote's newest
// build, and uninstalls it when the step goes.
func TestFlatpak(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			install := "dnf -y -q install flatpak"
			if !rpmImage(image) {
				install = "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -q flatpak"
			}
			h.exec("", "sh", "-c", install)
			h.exec(flatpakRepo, "sh", "-s", "hello")

			w := newWorkdir(t, "flatpak")
			w.writeAs("main.circuit.hcl", flatpakVars{h.port, h.keyFile, h.knownHosts, "present"})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			installed := func() string { return h.exec("", "flatpak", "list", "--system", "--columns=application,origin") }
			if out := installed(); !strings.Contains(out, "org.test.Hello\tlocal") {
				t.Fatalf("not installed:\n%s", out)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			// The remote gets a newer build. "present" is content with the
			// old one; "latest" fetches it.
			h.exec(flatpakRepo, "sh", "-s", "hello2")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan with a newer build at the remote:\n%s", out)
			}
			w.writeAs("main.circuit.hcl", flatpakVars{h.port, h.keyFile, h.knownHosts, "latest"})
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "cat", "/var/lib/flatpak/app/org.test.Hello/current/active/files/bin/hello"); !strings.Contains(got, "hello2") {
				t.Fatalf("not updated:\n%s", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after the update:\n%s", out)
			}

			// Someone uninstalls it by hand: drift, then repair.
			h.exec("", "flatpak", "uninstall", "-y", "--noninteractive", "--system", "org.test.Hello")
			if out, code := w.conn3x("drift", "-no-color"); code != 2 || !strings.Contains(out, "conn3x_flatpak.kiosk__hello") {
				t.Fatalf("drift exited %d:\n%s", code, out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if out := installed(); !strings.Contains(out, "org.test.Hello") {
				t.Fatalf("not reinstalled:\n%s", out)
			}

			w.writeAs("main.circuit.hcl", flatpakVars{h.port, h.keyFile, h.knownHosts, ""})
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if out := installed(); strings.Contains(out, "org.test.Hello") {
				t.Fatalf("still installed after removal:\n%s", out)
			}
		})
	}
}
