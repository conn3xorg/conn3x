// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type timezoneVars struct{ Port, KeyFile, KnownHosts, Zone string }

func TestTimezone(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "timezone")
			w.writeAs("main.circuit.hcl", timezoneVars{h.port, h.keyFile, h.knownHosts, "America/Argentina/Buenos_Aires"})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			if got := strings.TrimSpace(h.exec("", "date", "+%Z")); got != "-03" {
				t.Fatalf("date +%%Z = %q, want -03", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			w.writeAs("main.circuit.hcl", timezoneVars{h.port, h.keyFile, h.knownHosts, "Europe/Dublin"})
			out := w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, `conn3x_timezone.clock__zone["box"] will be updated in-place`) {
				t.Fatalf("zone change not planned as an update:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "readlink", "/etc/localtime"); !strings.HasSuffix(strings.TrimSpace(got), "zoneinfo/Europe/Dublin") {
				t.Fatalf("/etc/localtime -> %q", got)
			}
		})
	}
}
