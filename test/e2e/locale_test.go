// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type localeVars struct{ Port, KeyFile, KnownHosts, Package, Locale string }

func TestLocale(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			pkg, file := "locales", "/etc/default/locale"
			if rpmImage(image) {
				pkg, file = "glibc-langpack-en", "/etc/locale.conf"
			}
			w := newWorkdir(t, "locale")
			w.writeAs("main.circuit.hcl", localeVars{h.port, h.keyFile, h.knownHosts, pkg, "en_GB.UTF-8"})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			if got := h.exec("", "cat", file); !strings.Contains(got, "LANG=en_GB.UTF-8") && !strings.Contains(got, `LANG="en_GB.UTF-8"`) {
				t.Fatalf("%s = %q", file, got)
			}
			if got := strings.ToLower(h.exec("", "locale", "-a")); !strings.Contains(got, "en_gb.utf8") {
				t.Fatalf("en_GB.UTF-8 isn't installed; locale -a:\n%s", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			w.writeAs("main.circuit.hcl", localeVars{h.port, h.keyFile, h.knownHosts, pkg, "en_US.UTF-8"})
			out := w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, `conn3x_locale.lang__lang["box"] will be updated in-place`) {
				t.Fatalf("locale change not planned as an update:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after the change:\n%s", out)
			}
		})
	}
}
