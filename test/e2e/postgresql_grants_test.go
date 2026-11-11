// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type pgGrantsVars struct{ Port, KeyFile, KnownHosts, Tables string }

// TestPostgreSQLGrants gives a role privileges on a database, a schema and
// its tables, including tables made later by the schema's owner; names and
// revokes privileges granted by hand; and narrows the table privileges in
// a second apply.
func TestPostgreSQLGrants(t *testing.T) {
	for _, image := range []string{"rocky10", "ubuntu2404"} {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			psql := installPostgreSQL(t, h, image)
			psql("postgres", "CREATE ROLE migrator NOLOGIN")
			psql("postgres", "CREATE DATABASE shop OWNER migrator") // not inside a transaction
			psql("shop", "CREATE SCHEMA sales AUTHORIZATION migrator; SET ROLE migrator; CREATE TABLE sales.orders (id int)")
			has := func(sql string) string { t.Helper(); return psql("shop", "SELECT "+sql) }

			w := newWorkdir(t, "postgresql_grants")
			vars := pgGrantsVars{h.port, h.keyFile, h.knownHosts, `"SELECT", "INSERT", "UPDATE", "DELETE"`}
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			if got := has("has_database_privilege('app', 'shop', 'CONNECT'), has_schema_privilege('app', 'sales', 'USAGE'), has_schema_privilege('app', 'sales', 'CREATE')"); got != "t|t|f" {
				t.Fatalf("database and schema privileges: %q", got)
			}
			if got := has("has_table_privilege('app', 'sales.orders', 'INSERT'), has_table_privilege('app', 'sales.orders', 'TRUNCATE')"); got != "t|f" {
				t.Fatalf("table privileges: %q", got)
			}
			if out := w.mustConn3x("state", "show", `conn3x_postgresql_role.db__app_role["box"]`); !strings.Contains(out, `"shop.sales" = "migrator"`) {
				t.Fatalf("tables_created_by isn't the schema's owner:\n%s", out)
			}
			psql("shop", "SET ROLE migrator; CREATE TABLE sales.refunds (id int)")
			if got := has("has_table_privilege('app', 'sales.refunds', 'SELECT')"); got != "t" {
				t.Fatalf("a table made later has no default privileges: %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			// Privileges granted by hand are named on the plan, and revoked.
			psql("shop", "GRANT TRUNCATE ON sales.orders TO app; GRANT CREATE ON DATABASE shop TO app; GRANT USAGE ON SCHEMA public TO app")
			out := w.mustConn3x("plan", "-no-color")
			for _, want := range []string{"CREATE on database shop", "TRUNCATE on tables in shop.sales", "USAGE on schema shop.public", "1 to change"} {
				if !strings.Contains(out, want) {
					t.Fatalf("plan with privileges granted by hand doesn't say %q:\n%s", want, out)
				}
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			// PUBLIC has USAGE on public by default, so it's app's own grant
			// that's checked there, not whether app can use the schema.
			if got := has("has_table_privilege('app', 'sales.orders', 'TRUNCATE'), has_database_privilege('app', 'shop', 'CREATE'), EXISTS (SELECT FROM pg_namespace n, aclexplode(n.nspacl) a WHERE n.nspname = 'public' AND a.grantee = 'app'::regrole)"); got != "f|f|f" {
				t.Fatalf("privileges granted by hand after apply: %q", got)
			}

			// Narrowed to SELECT: the rest goes, from existing tables and
			// from the defaults for new ones.
			vars.Tables = `"SELECT"`
			w.writeAs("main.circuit.hcl", vars)
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, `- "INSERT"`) || !strings.Contains(out, "1 to change") {
				t.Fatalf("plan narrowing the table privileges:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			psql("shop", "SET ROLE migrator; CREATE TABLE sales.returns (id int)")
			if got := has("has_table_privilege('app', 'sales.orders', 'INSERT'), has_table_privilege('app', 'sales.refunds', 'SELECT'), has_table_privilege('app', 'sales.returns', 'INSERT'), has_table_privilege('app', 'sales.returns', 'SELECT')"); got != "f|t|f|t" {
				t.Fatalf("after narrowing: %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after narrowing:\n%s", out)
			}
		})
	}
}
