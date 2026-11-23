// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type packVars struct {
	Port, KeyFile, KnownHosts string
	Present                   bool
}

// pack packs a directory and a glob, plans clean, sees a changed file and
// a deleted archive as drift and packs again, and deletes the archive, not
// its files, when the step goes with on_remove = "delete".
func TestPack(t *testing.T) {
	for _, image := range []string{"rocky10", "debian13"} {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			h.exec("", "sh", "-c", "mkdir -p /backup /srv/data/sub /srv/data/cache /srv/logs && echo one > /srv/data/a && echo b > /srv/data/sub/b && echo c > /srv/data/cache/c && echo l > /srv/logs/app.log && echo x > /srv/logs/app.txt")
			w := newWorkdir(t, "pack")
			vars := packVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Present: true}
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			list := h.exec("", "tar", "-tzf", "/backup/data.tgz")
			for _, want := range []string{"data/a\n", "data/sub/b\n", "logs/app.log\n"} {
				if !strings.Contains(list, want) {
					t.Fatalf("archive lacks %q:\n%s", want, list)
				}
			}
			if strings.Contains(list, "cache") || strings.Contains(list, "app.txt") {
				t.Fatalf("archive holds what it shouldn't:\n%s", list)
			}
			if got := h.exec("", "stat", "-c", "%a", "/backup/data.tgz"); got != "640\n" {
				t.Fatalf("mode %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			h.exec("", "sh", "-c", "echo second > /srv/data/a")
			out := w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, "1 to change") || !strings.Contains(out, "sources_sha256") {
				t.Fatalf("plan after a file changed:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "tar", "-xzOf", "/backup/data.tgz", "data/a"); got != "second\n" {
				t.Fatalf("packed again, data/a is %q", got)
			}
			// A change below an excluded directory isn't drift.
			h.exec("", "sh", "-c", "echo more > /srv/data/cache/d")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after an excluded file changed:\n%s", out)
			}

			h.exec("", "rm", "/backup/data.tgz")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "1 to change") {
				t.Fatalf("plan with the archive gone:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			h.exec("", "test", "-f", "/backup/data.tgz")

			vars.Present = false
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if ls := h.exec("", "ls", "-A", "/backup"); ls != "" {
				t.Fatalf("on_remove = delete left:\n%s", ls)
			}
			h.exec("", "test", "-f", "/srv/data/a")
		})
	}
}
