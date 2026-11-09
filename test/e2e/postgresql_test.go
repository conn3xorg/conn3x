// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type postgresqlVars struct {
	Port, KeyFile, KnownHosts, Attributes, Password string
}

// The password has a quote and a space, so it only works quoted all the way.
const pgPassword = "s3cret 'quoted' pw"

// TestPostgreSQL makes a role and a database in the distribution's own
// PostgreSQL server, logs in as the role with its password, and takes an
// attribute away again.
func TestPostgreSQL(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			// The test images keep services from starting at install, so the
			// cluster is made and started here.
			install := `apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq postgresql >/dev/null &&
				v=$(ls /usr/lib/postgresql) && { [ -d /etc/postgresql/$v/main ] || pg_createcluster $v main >/dev/null; } &&
				systemctl enable --now postgresql@$v-main`
			if rpmImage(image) {
				install = "dnf install -y -q postgresql-server >/dev/null && postgresql-setup --initdb >/dev/null && systemctl enable --now postgresql"
			}
			// Red Hat's pg_hba.conf checks 127.0.0.1 with ident, so the role's
			// password login gets a line of its own above the others.
			h.exec("", "sh", "-c", install+` &&
				for i in $(seq 60); do runuser -u postgres -- psql -Xqc 'select 1' >/dev/null 2>&1 && break; sleep 1; done &&
				hba=$(runuser -u postgres -- psql -XtAc 'show hba_file') &&
				sed -i '1i host all app 127.0.0.1/32 scram-sha-256' "$hba" &&
				runuser -u postgres -- psql -Xqc 'select pg_reload_conf()' >/dev/null`)
			psql := func(sql string) string {
				return strings.TrimSpace(h.exec("", "runuser", "-u", "postgres", "--", "psql", "-XtAc", sql))
			}

			w := newWorkdir(t, "postgresql")
			w.writeAs("main.circuit.hcl", postgresqlVars{h.port, h.keyFile, h.knownHosts, `"CREATEDB"`, pgPassword})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			if got := psql("select rolcanlogin, rolcreatedb, rolsuper from pg_roles where rolname = 'app'"); got != "t|t|f" {
				t.Fatalf("role app: %q", got)
			}
			if got := psql("select pg_get_userbyid(datdba), pg_encoding_to_char(encoding) from pg_database where datname = 'app'"); got != "app|UTF8" {
				t.Fatalf("database app: %q", got)
			}
			if got := psql("select rolpassword from pg_authid where rolname = 'app'"); !strings.HasPrefix(got, "SCRAM-SHA-256$4096:") || strings.Contains(got, "s3cret") {
				t.Fatalf("stored password: %q", got)
			}
			if got := strings.TrimSpace(h.exec("", "env", "PGPASSWORD="+pgPassword, "psql", "-XtA", "-h", "127.0.0.1", "-U", "app", "-d", "app", "-c", "select current_user")); got != "app" {
				t.Fatalf("logging in as app: %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			w.writeAs("main.circuit.hcl", postgresqlVars{h.port, h.keyFile, h.knownHosts, "", pgPassword})
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := psql("select rolcreatedb from pg_roles where rolname = 'app'"); got != "f" {
				t.Fatalf("CREATEDB after taking it away: %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after the second apply:\n%s", out)
			}
		})
	}
}
