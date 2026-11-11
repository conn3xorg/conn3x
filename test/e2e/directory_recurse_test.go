// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type directoryRecurseVars struct{ Port, KeyFile, KnownHosts string }

// A recursive directory hands a whole tree to an account, with X for
// directories only; it leaves alone what a link points at and a file with
// another hard link. A path changed by hand is counted on the next plan.
func TestDirectoryRecurse(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "directory_recurse")
			w.writeAs("main.circuit.hcl", directoryRecurseVars{h.port, h.keyFile, h.knownHosts})
			w.mustConn3x("init", "-no-color")
			h.exec("", "sh", "-c", `id deploy >/dev/null 2>&1 || useradd -m deploy
mkdir -p -m 0777 /srv/app/releases/1 /srv/app/shared
echo x >/srv/app/releases/1/app.conf; chmod 0666 /srv/app/releases/1/app.conf
printf '#!/bin/sh\n' >/srv/app/releases/1/start; chmod 0755 /srv/app/releases/1/start
echo s >/root/secret; chmod 0600 /root/secret
ln /root/secret /srv/app/shared/hard
ln -s /root/secret /srv/app/shared/link`)

			w.mustConn3x("apply", "-auto-approve", "-no-color")
			got := h.exec("", "sh", "-c", "cd /srv/app && stat -c '%n %U %a' . releases releases/1 releases/1/app.conf releases/1/start shared; stat -c '%n %U' shared/link /root/secret")
			want := `. deploy 750
releases deploy 750
releases/1 deploy 750
releases/1/app.conf deploy 640
releases/1/start deploy 750
shared deploy 750
shared/link deploy
/root/secret root
`
			if got != want {
				t.Fatalf("after apply:\n%s\nwant:\n%s", got, want)
			}
			if got := h.exec("", "stat", "-c", "%a", "/root/secret"); got != "600\n" {
				t.Fatalf("the hard link's file is now %s", got)
			}
			out := w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, "No changes.") || !strings.Contains(out, "1 file(s) with another hard link") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			// A file changed by hand is counted, not named, and put back.
			h.exec("", "chmod", "0777", "/srv/app/releases/1/app.conf")
			out = w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, "1 path(s) under /srv/app") || strings.Contains(out, "app.conf") || !strings.Contains(out, "1 to change") {
				t.Fatalf("plan with a file changed by hand:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "stat", "-c", "%a", "/srv/app/releases/1/app.conf"); got != "750\n" {
				t.Fatalf("app.conf is %s after the second apply", got)
			}
		})
	}
}
