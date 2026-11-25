// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// A file step with source_path copies a file already on the host, plans
// clean after, sees a hand edit of the copy and a change to the source,
// and names a source that's gone (#1349).
func TestFileSourcePath(t *testing.T) {
	for _, image := range []string{"ubuntu2404", "rocky10"} {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			h.exec("", "sh", "-c", "getent group adm >/dev/null || groupadd adm; mkdir -p /usr/share/doc/app && printf 'listen = 80\\n' > /usr/share/doc/app/app.conf.sample")
			w := newWorkdir(t, "file_source_path")
			w.writeAs("main.circuit.hcl", fetchVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "sh", "-c", "cat /etc/app/app.conf; stat -c '%a %G' /etc/app/app.conf"); got != "listen = 80\n640 adm\n" {
				t.Fatalf("after apply: %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			h.exec("", "sh", "-c", "echo 'listen = 8080' > /etc/app/app.conf")
			out := w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, `app_conf["box"] will be updated`) || !strings.Contains(out, "sha256") || !strings.Contains(out, "1 to change") {
				t.Fatalf("plan after a hand edit:\n%s", out)
			}
			if strings.Contains(out, "listen") {
				t.Fatalf("the plan shows file content:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "sh", "-c", "cat /etc/app/app.conf; cat /etc/app/app.conf.conn3x-*~"); got != "listen = 80\nlisten = 8080\n" {
				t.Fatalf("after restoring, the copy and its backup: %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after restoring:\n%s", out)
			}

			h.exec("", "sh", "-c", "echo 'listen = 81' > /usr/share/doc/app/app.conf.sample")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "1 to change") || !strings.Contains(out, "source_sha256") {
				t.Fatalf("plan after a source change:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "cat", "/etc/app/app.conf"); got != "listen = 81\n" {
				t.Fatalf("after copying the new source: %q", got)
			}

			h.exec("", "rm", "/usr/share/doc/app/app.conf.sample")
			out, code := w.conn3x("apply", "-auto-approve", "-no-color")
			if code == 0 || !strings.Contains(out, "source_path /usr/share/doc/app/app.conf.sample doesn't exist on the host") {
				t.Fatalf("apply with the source gone exited %d:\n%s", code, out)
			}
			if got := h.exec("", "cat", "/etc/app/app.conf"); got != "listen = 81\n" {
				t.Fatalf("a failed copy changed the file: %q", got)
			}
		})
	}
}

// A copy whose mode drifted, behind an earlier step that rewrites its
// source in the same apply, copies the new source instead of failing
// with OpenTofu's "inconsistent result" (#1376).
func TestFileSourcePathEarlierStep(t *testing.T) {
	h := startHost(t, "ubuntu2404")
	w := newWorkdir(t, "file_source_path_earlier")
	vars := fileVars{Content: `listen = 80\n`, Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}

	h.exec("", "chmod", "0600", "/etc/app/app.conf")
	vars.Content = `listen = 81\n`
	w.writeAs("main.circuit.hcl", vars)
	if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code != 0 {
		t.Fatalf("apply exited %d:\n%s", code, out)
	}
	if got := h.exec("", "sh", "-c", "cat /etc/app/app.conf; stat -c %a /etc/app/app.conf"); got != "listen = 81\n640\n" {
		t.Fatalf("after apply: %q", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after the second apply:\n%s", out)
	}
}

// A path and a source_path with a backslash and a space in them copy,
// plan clean and show a hand edit, though sha256sum given such a name
// prints its hash with a "\" in front (#1385).
func TestFileSourcePathBackslash(t *testing.T) {
	for _, image := range []string{"ubuntu2404", "rocky10"} {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			h.exec("", "sh", "-c", `mkdir -p /usr/share/doc/app && printf 'listen = 80\n' > '/usr/share/doc/app/a\b c.sample'`)
			w := newWorkdir(t, "file_source_path_backslash")
			w.writeAs("main.circuit.hcl", fetchVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "cat", `/etc/app/a\b c.conf`); got != "listen = 80\n" {
				t.Fatalf("after apply: %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}
			h.exec("", "sh", "-c", `echo 'listen = 8080' > '/etc/app/a\b c.conf'`)
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, `app_conf["box"] will be updated`) || !strings.Contains(out, "1 to change") {
				t.Fatalf("plan after a hand edit:\n%s", out)
			}
		})
	}
}
