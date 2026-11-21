// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type userAgingVars struct {
	Port, KeyFile, KnownHosts string
	Min, Max, Warn            int
}

// A CIS password maximum on an account that already exists, which
// PASS_MAX_DAYS can't reach (#1184). A hand chage plans a change back, and
// -1 clears a limit.
func TestUserPasswordAging(t *testing.T) {
	for _, distro := range []string{"rocky10", "ubuntu2404"} {
		t.Run(distro, func(t *testing.T) {
			h := startHost(t, distro)
			aging := func() string {
				return strings.TrimSpace(h.exec("", "sh", "-c", "getent shadow conn3xa | cut -d: -f4,5,6"))
			}
			w := newWorkdir(t, "user-aging")
			write := func(min, max, warn int) {
				w.writeAs("main.circuit.hcl", userAgingVars{h.port, h.keyFile, h.knownHosts, min, max, warn})
			}
			clean := func(when string) {
				t.Helper()
				if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
					t.Fatalf("plan %s:\n%s", when, out)
				}
			}

			write(1, 365, 7)
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := aging(); got != "1:365:7" {
				t.Fatalf("after applying min 1, max 365, warn 7: %q", got)
			}
			clean("after applying")

			h.exec("", "chage", "-M", "99999", "conn3xa")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "password_max_days") {
				t.Fatalf("a hand chage -M plans nothing:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := aging(); got != "1:365:7" {
				t.Fatalf("after putting it back: %q", got)
			}

			write(-1, -1, -1)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := aging(); got != "::" {
				t.Fatalf("after clearing every limit: %q", got)
			}
			clean("after clearing")
		})
	}
}
