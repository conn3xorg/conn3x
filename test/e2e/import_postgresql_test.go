// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type importPostgresqlVars struct {
	Port, KeyFile, KnownHosts string
	Become                    bool
	Database, Password        string
}

// TestImportPostgreSQL adopts a role and a database made by hand. Reading
// them needs root, so without become the plan says so. The import leaves
// the role's password alone, and a step that then sets password_wo shows
// password_hmac changing and sets it. A database the server doesn't have
// is refused.
func TestImportPostgreSQL(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			addDeploy(h, "", "")
			install := `apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq postgresql >/dev/null &&
				v=$(ls /usr/lib/postgresql) && { [ -d /etc/postgresql/$v/main ] || pg_createcluster $v main >/dev/null; } &&
				systemctl enable --now postgresql@$v-main`
			if rpmImage(image) {
				install = "dnf install -y -q postgresql-server >/dev/null && postgresql-setup --initdb >/dev/null && systemctl enable --now postgresql"
			}
			h.exec("", "sh", "-c", install+` &&
				for i in $(seq 60); do runuser -u postgres -- psql -Xqc 'select 1' >/dev/null 2>&1 && break; sleep 1; done`)
			psql := func(sql string) string {
				return strings.TrimSpace(h.exec("", "runuser", "-u", "postgres", "--", "psql", "-XtAc", sql))
			}
			psql("create role app login createdb password 'made by hand'")
			psql("create database app owner app encoding 'UTF8' template template0")
			before := psql("select rolpassword from pg_authid where rolname = 'app'")

			w := newWorkdir(t, "import_postgresql")
			vars := importPostgresqlVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Database: "app"}
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")

			out, code := w.conn3x("plan", "-no-color")
			if code == 0 || !strings.Contains(out, "set become = true") {
				t.Fatalf("plan without become (exit %d) should ask for it:\n%s", code, out)
			}

			vars.Become = true
			w.writeAs("main.circuit.hcl", vars)
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "2 to import, 0 to add, 0 to change, 0 to destroy") {
				t.Fatalf("plan with become:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after the import:\n%s", out)
			}
			if got := psql("select rolpassword from pg_authid where rolname = 'app'"); got != before {
				t.Fatal("the import changed the role's password")
			}

			vars.Password = "set by the step"
			w.writeAs("main.circuit.hcl", vars)
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "password_hmac") || !strings.Contains(out, "1 to change") {
				t.Fatalf("plan after adding password_wo:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := psql("select rolpassword from pg_authid where rolname = 'app'"); got == before {
				t.Fatal("password_wo didn't change the role's password")
			}

			missing := newWorkdir(t, "import_postgresql")
			vars.Database = "missing"
			missing.writeAs("main.circuit.hcl", vars)
			missing.mustConn3x("init", "-no-color")
			if out, code := missing.conn3x("plan", "-no-color"); code == 0 || !strings.Contains(out, "PostgreSQL database missing") {
				t.Fatalf("plan importing a missing database (exit %d):\n%s", code, out)
			}
		})
	}
}
