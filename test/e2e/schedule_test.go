// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type scheduleVars struct{ Port, KeyFile, KnownHosts, CronPackage string }

func TestCronAndTimer(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "schedule")
			cron := "cron"
			if rpmImage(image) {
				cron = "cronie"
			}
			w.writeAs("main.circuit.hcl", scheduleVars{h.port, h.keyFile, h.knownHosts, cron})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			if got := h.exec("", "cat", "/etc/cron.d/conn3x-cleanup"); !strings.HasSuffix(got, "15 3 * * * root find /tmp -mtime +7 -delete\n") {
				t.Fatalf("cron file = %q", got)
			}
			for _, check := range [][]string{{"is-enabled", "conn3x-report.timer"}, {"is-active", "conn3x-report.timer"}} {
				if got := strings.TrimSpace(h.exec("", append([]string{"systemctl"}, check...)...)); got != "enabled" && got != "active" {
					t.Fatalf("systemctl %v = %s", check, got)
				}
			}
			h.exec("", "systemctl", "start", "conn3x-report.service")
			h.exec("", "test", "-s", "/var/tmp/conn3x-report")

			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}
			h.exec("", "systemctl", "stop", "conn3x-report.timer")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, `conn3x_timer.jobs__report["box"] will be updated in-place`) {
				t.Fatalf("stopped timer not planned:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			// A drop-in that only adds, as circuits write for a random delay
			// or sandboxing, leaves the step's settings alone: not drift.
			h.exec("", "sh", "-c", "mkdir -p /etc/systemd/system/conn3x-report.timer.d /etc/systemd/system/conn3x-report.service.d && printf '[Timer]\\nRandomizedDelaySec=1min\\n' > /etc/systemd/system/conn3x-report.timer.d/delay.conf && printf '[Service]\\nProtectSystem=strict\\n' > /etc/systemd/system/conn3x-report.service.d/sandbox.conf && systemctl daemon-reload")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("an additive drop-in shouldn't be drift:\n%s", out)
			}

			// A drop-in from systemctl edit retimes the job behind the step:
			// that's drift, and apply refuses rather than pretend (#850).
			h.exec("", "sh", "-c", "mkdir -p /etc/systemd/system/conn3x-report.timer.d && printf '[Timer]\\nOnCalendar=\\nOnCalendar=hourly\\n' > /etc/systemd/system/conn3x-report.timer.d/override.conf")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, `conn3x_timer.jobs__report["box"] will be updated in-place`) {
				t.Fatalf("a drop-in should be drift:\n%s", out)
			}
			if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code == 0 || !strings.Contains(out, "conn3x-report.timer.d") {
				t.Fatalf("apply with a drop-in (exit %d):\n%s", code, out)
			}
		})
	}
}
