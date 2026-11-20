// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type mysqlVariableVars struct {
	Port, KeyFile, KnownHosts string
	Persist                   bool
	SQLMode                   string
}

// TestMySQLVariable sets max_connections in every image's server; plans
// clean; puts back a change made by hand; and resets it on destroy. On
// Ubuntu's MySQL 8 it also persists a boolean and writes a startup-only
// size to mysqld-auto.cnf alone. On MariaDB, which has no SET PERSIST,
// the persist modes fail and say so.
func TestMySQLVariable(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			install := `apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq mariadb-server && systemctl enable --now mariadb`
			mysql8 := image == "ubuntu2404"
			switch {
			case mysql8:
				install = `apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq mysql-server && systemctl enable --now mysql`
			case rpmImage(image):
				install = "dnf install -y -q mariadb-server && systemctl enable --now mariadb"
			}
			h.exec("", "sh", "-c", `timeout 300 sh -c "$1" >/tmp/install.log 2>&1 || { echo "install failed or hung: $?"; tail -n 20 /tmp/install.log; ps -eo pid,etime,stat,args; tail -n 30 /var/log/mysql/error.log /var/log/mariadb/mariadb.log /var/log/apt/term.log /var/log/dnf.log 2>/dev/null; exit 1; }`, "sh",
				install+` && for i in $(seq 60); do mysql -u root -e 'select 1' >/dev/null 2>&1 && break; sleep 1; done`)
			const cli = `"$(command -v mariadb || command -v mysql)"`
			sql := func(q string) string {
				return strings.TrimSpace(h.exec(q, "sh", "-c", cli+" -u root -N -B"))
			}

			w := newWorkdir(t, "mysql_variable")
			w.writeAs("main.circuit.hcl", mysqlVariableVars{h.port, h.keyFile, h.knownHosts, mysql8, ""})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := sql("select @@global.max_connections"); got != "500" {
				t.Fatalf("max_connections: %q", got)
			}
			if mysql8 {
				if got := sql("select @@global.slow_query_log"); got != "1" {
					t.Fatalf("slow_query_log: %q", got)
				}
				persisted := sql("select VARIABLE_NAME, VARIABLE_VALUE from performance_schema.persisted_variables where VARIABLE_NAME in ('slow_query_log', 'innodb_log_buffer_size') order by 1")
				if persisted != "innodb_log_buffer_size\t33554432\nslow_query_log\tON" {
					t.Fatalf("mysqld-auto.cnf: %q", persisted)
				}
				if got := sql("select @@global.innodb_log_buffer_size"); got == "33554432" {
					t.Fatal("persist_only changed the running value")
				}
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			// A change by hand shows in the plan, and the apply puts it back.
			sql("set global max_connections = 200")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "max_connections") {
				t.Fatalf("a hand change isn't planned back:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := sql("select @@global.max_connections"); got != "500" {
				t.Fatalf("max_connections after the second apply: %q", got)
			}

			// sql_mode in another order than the server keeps it, then a
			// combination mode the server expands: both plan clean (#1150).
			for _, mode := range []string{"NO_ENGINE_SUBSTITUTION,STRICT_TRANS_TABLES", "TRADITIONAL"} {
				w.writeAs("main.circuit.hcl", mysqlVariableVars{h.port, h.keyFile, h.knownHosts, mysql8, mode})
				w.mustConn3x("apply", "-auto-approve", "-no-color")
				if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
					t.Fatalf("plan after sql_mode %s (server has %q):\n%s", mode, sql("select @@global.sql_mode"), out)
				}
			}
			t.Logf("TRADITIONAL on this server: %s", sql("select @@global.sql_mode"))
			w.writeAs("main.circuit.hcl", mysqlVariableVars{h.port, h.keyFile, h.knownHosts, mysql8, ""})

			w.mustConn3x("destroy", "-auto-approve", "-no-color")
			if got := sql("select @@global.max_connections"); got != "151" {
				t.Fatalf("max_connections after destroy: %q, want the default 151", got)
			}

			if !mysql8 {
				m := newWorkdir(t, "mysql_variable")
				m.writeAs("main.circuit.hcl", mysqlVariableVars{h.port, h.keyFile, h.knownHosts, true, ""})
				m.mustConn3x("init", "-no-color")
				out, code := m.conn3x("apply", "-auto-approve", "-no-color")
				if code == 0 || !strings.Contains(out, "MariaDB has no SET PERSIST") {
					t.Fatalf("persist on MariaDB: exit %d\n%s", code, out)
				}
			}
		})
	}
}
