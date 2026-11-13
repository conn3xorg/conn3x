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

type dircopyVars struct {
	Port, KeyFile, KnownHosts string
	Present                   bool
}

// A directory_copy step copies a tree, binary files included; the next
// plan has nothing to do; a file edited on the host and a stray one are
// named in the plan, then put right; a file changed in the source is
// named too; and removing the step removes the files it copied.
func TestDirectoryCopy(t *testing.T) {
	for _, image := range []string{"rocky10", "ubuntu2404"} {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "directory_copy")
			vars := dircopyVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Present: true}
			w.writeAs("main.circuit.hcl", vars)
			src := filepath.Join(w.dir, "site")
			for rel, body := range map[string]string{"index.html": "<h1>hi</h1>\n", "img/logo.bin": "\x00\x01\xff\n", "css/a b.css": "body{}\n"} {
				if err := os.MkdirAll(filepath.Dir(filepath.Join(src, rel)), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(src, rel), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "sh", "-c", "cd /srv/site && find . -type f -printf '%P %u %m\\n' | sort"); got != "css/a b.css nobody 644\nimg/logo.bin nobody 644\nindex.html nobody 644\n" {
				t.Fatalf("on the host:\n%s", got)
			}
			if got := h.exec("", "od", "-An", "-tx1", "/srv/site/img/logo.bin"); strings.Fields(got)[2] != "ff" {
				t.Fatalf("binary file: %s", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			h.exec("edited\n", "sh", "-c", "cat > /srv/site/index.html; echo x > /srv/site/stray.txt")
			out := w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, `"index.html"`) || !strings.Contains(out, `"stray.txt"`) || !strings.Contains(out, "1 to change") {
				t.Fatalf("plan after a hand edit:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "sh", "-c", "cat /srv/site/index.html; ls /srv/site"); got != "<h1>hi</h1>\ncss\nimg\nindex.html\n" {
				t.Fatalf("after putting it right:\n%s", got)
			}

			if err := os.WriteFile(filepath.Join(src, "index.html"), []byte("<h1>v2</h1>\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, `"index.html"`) || !strings.Contains(out, "1 to change") {
				t.Fatalf("plan after a source change:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "cat", "/srv/site/index.html"); got != "<h1>v2</h1>\n" {
				t.Fatalf("source change: %q", got)
			}

			vars.Present = false
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "sh", "-c", "find /srv/site -type f | wc -l"); strings.TrimSpace(got) != "0" {
				t.Fatalf("files left after removing the step: %s", got)
			}
		})
	}
}
