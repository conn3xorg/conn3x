// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// TestPostgreSQLExtension creates pgcrypto in a database, plans clean, and
// drops it when the step goes. Rocky and Fedora ship pgcrypto in
// postgresql-contrib, so there the first apply fails with the hint to
// install a package, and the second, after that, works.
func TestPostgreSQLExtension(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			psqlIn := installPostgreSQL(t, h, image)

			w := newWorkdir(t, "postgresql_extension")
			w.writeAs("main.circuit.hcl", circuitVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts})
			w.mustConn3x("init", "-no-color")
			if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code != 0 {
				if !strings.Contains(out, "package step") {
					t.Fatalf("apply failed without the package hint:\n%s", out)
				}
				t.Log("pgcrypto needed postgresql-contrib")
				h.exec("", "sh", "-c", "dnf install -y -q postgresql-contrib >/dev/null")
				w.mustConn3x("apply", "-auto-approve", "-no-color")
			}
			if got := psqlIn("app", "select extname from pg_extension where extname = 'pgcrypto'"); got != "pgcrypto" {
				t.Fatalf("pgcrypto in app: %q", got)
			}
			if got := psqlIn("app", "select encode(digest('a', 'sha256'), 'hex')"); !strings.HasPrefix(got, "ca978112") {
				t.Fatalf("digest: %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}
			w.mustConn3x("destroy", "-auto-approve", "-no-color")
			if got := psqlIn("app", "select count(*) from pg_extension where extname = 'pgcrypto'"); got != "0" {
				t.Fatalf("pgcrypto after destroy: %q", got)
			}
		})
	}
}
