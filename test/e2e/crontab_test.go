// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type crontabVars struct {
	Port, KeyFile, KnownHosts string
	Present                   bool
	OnRemove                  string
}

// A crontab step owns the whole of a user's crontab: a job added by hand is
// named on the next plan, by schedule and first word only, and removed;
// comments stay. Without the crontab command it says what to install.
// Removing the step leaves the crontab, unless on_remove is "delete".
func TestCrontab(t *testing.T) {
	for _, image := range []string{"rocky10", "ubuntu2404"} {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "crontab")
			vars := crontabVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Present: true}
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")
			h.exec("", "sh", "-c", "id deploy >/dev/null 2>&1 || useradd -m deploy")

			pkg := "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cron >/dev/null"
			if rpmImage(image) {
				pkg = "dnf install -y -q cronie >/dev/null"
			}
			if strings.TrimSpace(h.exec("", "sh", "-c", "command -v crontab || true")) == "" {
				out, code := w.conn3x("apply", "-auto-approve", "-no-color")
				if code == 0 || !strings.Contains(out, "install cron (Debian, Ubuntu) or cronie") {
					t.Fatalf("apply without a crontab command (exit %d):\n%s", code, out)
				}
				h.exec("", "sh", "-c", pkg)
			}

			byHand := "*/5 * * * * curl -s https://example.com/ping?token=s3cret"
			h.exec("# my notes\n"+byHand+"\n", "crontab", "-u", "deploy", "-")
			crontab := func() string { return h.exec("", "crontab", "-u", "deploy", "-l") }

			w.mustConn3x("apply", "-auto-approve", "-no-color")
			want := "# my notes\nMAILTO=ops@example.com\n# conn3x: backup\n0 3 * * * /opt/app/backup --at 50\\%\n# conn3x: boot\n@reboot /opt/app/start\n"
			if got := crontab(); got != want {
				t.Fatalf("deploy's crontab:\n%s\nwant:\n%s", got, want)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			// A job added by hand is named on the next plan, and removed.
			h.exec(want+byHand+"\n", "crontab", "-u", "deploy", "-")
			out := w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, "*/5 * * * * curl …") || strings.Contains(out, "s3cret") || !strings.Contains(out, "1 to change") {
				t.Fatalf("plan with a job added by hand:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := crontab(); got != want {
				t.Fatalf("the job added by hand is still there:\n%s", got)
			}
			if state := w.mustConn3x("state", "pull"); strings.Contains(state, "s3cret") || strings.Contains(state, "curl") {
				t.Fatalf("state keeps the job added by hand:\n%s", state)
			}

			// Removing the step leaves the crontab.
			vars.Present = false
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := crontab(); got != want {
				t.Fatalf("deploy's crontab after removing the step:\n%s", got)
			}

			// With on_remove = "delete", removing it removes the crontab.
			vars.Present, vars.OnRemove = true, "delete"
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			vars.Present = false
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "sh", "-c", "crontab -u deploy -l >/dev/null 2>&1 && echo has || echo none"); got != "none\n" {
				t.Fatalf("deploy still has a crontab after removing a step with on_remove = \"delete\": %s", got)
			}
		})
	}
}
