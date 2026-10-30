// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type editVars struct {
	Port, KeyFile, KnownHosts string
	WithLine                  bool
}

func TestLineAndBlock(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "edit")
			vars := editVars{h.port, h.keyFile, h.knownHosts, true}
			// A file the system owns; the circuit only edits parts of it.
			h.exec("# app\nport = 80\nname = demo\n", "sh", "-c", "cat > /etc/conn3x-app.conf")
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			want := "# app\nport = 8080\nname = demo\n# BEGIN CONN3X MANAGED BLOCK\nworkers = 4\ntimeout = 30\n# END CONN3X MANAGED BLOCK\n"
			if got := h.exec("", "cat", "/etc/conn3x-app.conf"); got != want {
				t.Fatalf("file = %q", got)
			}

			out := w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply is not empty:\n%s", out)
			}

			h.exec("", "sh", "-c", "sed -i 's/^workers = 4/workers = 99/' /etc/conn3x-app.conf")
			if out = w.mustConn3x("plan", "-no-color"); !strings.Contains(out, `conn3x_block.cfg__tuning["box"] will be updated in-place`) {
				t.Fatalf("block drift not planned:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			// Removing the line step with on_remove = "delete" takes the line out.
			vars.WithLine = false
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			want = "# app\nname = demo\n# BEGIN CONN3X MANAGED BLOCK\nworkers = 4\ntimeout = 30\n# END CONN3X MANAGED BLOCK\n"
			if got := h.exec("", "cat", "/etc/conn3x-app.conf"); got != want {
				t.Fatalf("after removing the line step: %q", got)
			}
		})
	}
}

// A line or block on a symlink writes to the file it points to. The link stays
// and so does the target's mode and owner; replacing the link used to leave a
// regular file of mode 0777.
func TestLineAndBlockThroughSymlink(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "edit_symlink")
			vars := editVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, WithLine: true}
			h.exec("port = 80\n", "sh", "-c", "cat > /etc/conn3x-real.conf; chmod 0640 /etc/conn3x-real.conf; chown root:daemon /etc/conn3x-real.conf; ln -s /etc/conn3x-real.conf /etc/conn3x-link.conf")
			check := func(when, wantContent string) {
				t.Helper()
				if got := h.exec("", "cat", "/etc/conn3x-real.conf"); got != wantContent {
					t.Fatalf("%s: file = %q", when, got)
				}
				if got := h.exec("", "sh", "-c", "stat -c '%a %U %G' /etc/conn3x-real.conf; readlink /etc/conn3x-link.conf"); got != "640 root daemon\n/etc/conn3x-real.conf\n" {
					t.Fatalf("%s: mode and link = %q", when, got)
				}
			}
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			block := "# BEGIN CONN3X MANAGED BLOCK\nworkers = 4\n# END CONN3X MANAGED BLOCK\n"
			check("after apply", "port = 8080\n"+block)
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply is not empty:\n%s", out)
			}

			// Drift is read through the link, and so is the repair.
			h.exec("", "sh", "-c", "sed -i 's/^workers = 4/workers = 99/' /etc/conn3x-real.conf")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, `conn3x_block.cfg__tuning["box"] will be updated in-place`) {
				t.Fatalf("block drift not planned:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			check("after fixing drift", "port = 8080\n"+block)

			// on_remove = "delete" goes through the link too.
			vars.WithLine = false
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			check("after removing the line step", block)

			// Someone the old bug hit has a regular file of mode 0777 where the
			// link was. It reads as in sync, so a plan stays quiet: Conn3x has no
			// record it was ever a link, which is why the release notes ask
			// people to look.
			h.exec("", "sh", "-c", "rm /etc/conn3x-link.conf; cp /etc/conn3x-real.conf /etc/conn3x-link.conf; chmod 0777 /etc/conn3x-link.conf")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan on a file the old bug left is not empty:\n%s", out)
			}
		})
	}
}

type iniVars struct {
	Port, KeyFile, KnownHosts string
	Grow                      bool
}

func TestIniAndReplace(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "ini_replace")
			vars := iniVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts}
			h.exec("# app settings\n[main]\n; the port\nport = 80\nname = demo\n\n[other]\nport = 1\n", "sh", "-c", "cat > /etc/conn3x-app.ini; chmod 0640 /etc/conn3x-app.ini; chown root:daemon /etc/conn3x-app.ini")
			h.exec("old.example.com a\nold.example.com b\nkeep\n", "sh", "-c", "cat > /etc/conn3x-real.conf; chmod 0600 /etc/conn3x-real.conf; ln -s /etc/conn3x-real.conf /etc/conn3x-link.conf")
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			wantINI := "# app settings\n[main]\n; the port\nport = 8080\nname = demo\n\n[other]\nport = 1\n[new]\nkey=v\n"
			wantConf := "new.example.com:443 a\nnew.example.com:443 b\nkeep\n"
			check := func(when string) {
				t.Helper()
				if got := h.exec("", "cat", "/etc/conn3x-app.ini"); got != wantINI {
					t.Fatalf("%s: ini file = %q", when, got)
				}
				if got := h.exec("", "cat", "/etc/conn3x-real.conf"); got != wantConf {
					t.Fatalf("%s: replaced file = %q", when, got)
				}
				if got := h.exec("", "sh", "-c", "stat -c '%a %U %G' /etc/conn3x-app.ini /etc/conn3x-real.conf; readlink /etc/conn3x-link.conf"); got != "640 root daemon\n600 root root\n/etc/conn3x-real.conf\n" {
					t.Fatalf("%s: modes and link = %q", when, got)
				}
			}
			check("after apply")
			if got := h.exec("", "sh", "-c", "test -e /etc/conn3x-never.ini && echo there || echo missing"); got != "missing\n" {
				t.Fatalf("removing an option created the file: %s", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply is not empty:\n%s", out)
			}
			if out, code := w.conn3x("drift", "-no-color"); code != 0 {
				t.Fatalf("drift right after apply exited %d:\n%s", code, out)
			}

			// Hand edits show up, and an apply puts them right.
			h.exec("", "sh", "-c", "sed -i 's/^port = 8080/port = 99/' /etc/conn3x-app.ini; echo old.example.com c >> /etc/conn3x-real.conf")
			out, code := w.conn3x("drift", "-no-color")
			if code != 2 {
				t.Fatalf("drift after a hand edit exited %d, want 2:\n%s", code, out)
			}
			for _, want := range []string{`conn3x_ini.cfg__port["box"]`, `conn3x_replace.cfg__mirror["box"]`} {
				if !strings.Contains(out, want) {
					t.Fatalf("drift output is missing %q:\n%s", want, out)
				}
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			wantConf += "new.example.com:443 c\n"
			check("after fixing drift")

			// A replacement that matches its own output is stopped, with the
			// file untouched, rather than growing on every plan.
			vars.Grow = true
			w.writeAs("main.circuit.hcl", vars)
			if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code == 0 || !strings.Contains(out, "still matches") {
				t.Fatalf("a replacement that never settles applied, exit %d:\n%s", code, out)
			}
			check("after the refused replace")
		})
	}
}
