// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// TestPostgreSQLSchema creates a schema in a database, owned by a role,
// and a second role granted USAGE on it in the same run; plans clean; and
// drops the schema when the step goes.
func TestPostgreSQLSchema(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			psqlIn := installPostgreSQL(t, h, image)

			w := newWorkdir(t, "postgresql_schema")
			w.writeAs("main.circuit.hcl", circuitVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			owner := psqlIn("app", "select pg_get_userbyid(nspowner) from pg_namespace where nspname = 'reporting'")
			if owner != "app" {
				t.Fatalf("reporting's owner: %q", owner)
			}
			if got := psqlIn("app", "select has_schema_privilege('reporter', 'reporting', 'USAGE')"); got != "t" {
				t.Fatalf("reporter's USAGE on reporting: %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}
			// A new owner by hand shows in the plan, and the apply puts it back.
			psqlIn("app", "alter schema reporting owner to postgres")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "reporting_schema") {
				t.Fatalf("an owner changed by hand isn't planned back:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := psqlIn("app", "select pg_get_userbyid(nspowner) from pg_namespace where nspname = 'reporting'"); got != "app" {
				t.Fatalf("owner after the second apply: %q", got)
			}
			w.mustConn3x("destroy", "-auto-approve", "-no-color")
			if got := psqlIn("app", "select count(*) from pg_namespace where nspname = 'reporting'"); got != "0" {
				t.Fatalf("reporting after destroy: %q", got)
			}
		})
	}
}
