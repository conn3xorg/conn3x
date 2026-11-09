// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type mysqlVars struct {
	Port, KeyFile, KnownHosts, Privileges, Password string
}

// The password has a quote, a backslash and spaces, so it only works quoted
// all the way, with backslashes read as plain text. In the HCL template the
// backslash is written twice.
const (
	mysqlPassword = `s3cret 'quoted' \n pw`
	mysqlHCLPw    = `s3cret 'quoted' \\n pw`
)

// TestMySQL makes a database and a user with grants in the distribution's
// own server, MySQL on Ubuntu and MariaDB elsewhere, logs in as the user
// with its password, and narrows its grant again.
func TestMySQL(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			// The test images keep services from starting at install.
			install := `apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq mariadb-server >/dev/null && systemctl enable --now mariadb`
			switch {
			case image == "ubuntu2404":
				// On a host with its own MySQL AppArmor profile loaded, as CI's
				// runner has, the postinst can't stop its temporary mysqld and
				// the install hangs. ci.yml unloads that profile first.
				install = `apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq mysql-server >/dev/null && systemctl enable --now mysql`
			case rpmImage(image):
				install = "dnf install -y -q mariadb-server >/dev/null && systemctl enable --now mariadb"
			}
			// A server that hangs at install fails this test, not the suite,
			// and says where it was.
			h.exec("", "sh", "-c", `timeout 300 sh -c "$1" || { echo "install failed or hung: $?"; ps -eo pid,etime,stat,args; tail -n 40 /var/log/mysql/error.log; tail -n 30 /var/log/apt/term.log; exit 1; }`, "sh",
				install+` && for i in $(seq 60); do mysql -u root -e 'select 1' >/dev/null 2>&1 && break; sleep 1; done`)
			// MariaDB's own name for the client, where it has one, skips a warning.
			const cli = `"$(command -v mariadb || command -v mysql)"`
			sql := func(q string) string {
				return strings.TrimSpace(h.exec(q, "sh", "-c", cli+" -u root -N -B"))
			}

			w := newWorkdir(t, "mysql")
			w.writeAs("main.circuit.hcl", mysqlVars{h.port, h.keyFile, h.knownHosts, `"ALL PRIVILEGES"`, mysqlHCLPw})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			if got := sql("select DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME from information_schema.SCHEMATA where SCHEMA_NAME = 'app'"); got != "utf8mb4\tutf8mb4_bin" {
				t.Fatalf("database app: %q", got)
			}
			if got := sql("show grants for 'app'@'127.0.0.1'"); !strings.Contains(got, "GRANT ALL PRIVILEGES ON `app`.* TO") {
				t.Fatalf("grants: %q", got)
			}
			login := func() string {
				return strings.TrimSpace(h.exec("select current_user()", "env", "MYSQL_PWD="+mysqlPassword, "sh", "-c", cli+" -h 127.0.0.1 -u app -N -B app"))
			}
			if got := login(); got != "app@127.0.0.1" {
				t.Fatalf("logging in as app: %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			w.writeAs("main.circuit.hcl", mysqlVars{h.port, h.keyFile, h.knownHosts, `"SELECT"`, mysqlHCLPw})
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := sql("show grants for 'app'@'127.0.0.1'"); !strings.Contains(got, "GRANT SELECT ON `app`.* TO") || strings.Contains(got, "ALL PRIVILEGES") {
				t.Fatalf("grants after narrowing: %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after the second apply:\n%s", out)
			}
			if got := login(); got != "app@127.0.0.1" {
				t.Fatalf("logging in as app after the change: %q", got)
			}
		})
	}
}
