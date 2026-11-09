// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type importMysqlVars struct {
	Port, KeyFile, KnownHosts string
	Become                    bool
	Host, Password            string
}

// TestImportMySQL adopts a database and an account made by hand. Reading
// them logs in as root over the socket, so without become the plan says so.
// The import leaves the account's password alone, and a step that then sets
// password_wo shows password_hmac changing and sets it. An account is its
// name and host together, so app@localhost isn't app@%, and importing it is
// refused.
func TestImportMySQL(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			addDeploy(h, "", "")
			install := `apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq mariadb-server >/dev/null && systemctl enable --now mariadb`
			switch {
			case image == "ubuntu2404":
				install = `apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq mysql-server >/dev/null && systemctl enable --now mysql`
			case rpmImage(image):
				install = "dnf install -y -q mariadb-server >/dev/null && systemctl enable --now mariadb"
			}
			h.exec("", "sh", "-c", `timeout 300 sh -c "$1" || { echo "install failed or hung: $?"; exit 1; }`, "sh",
				install+` && for i in $(seq 60); do mysql -u root -e 'select 1' >/dev/null 2>&1 && break; sleep 1; done`)
			const cli = `"$(command -v mariadb || command -v mysql)"`
			sql := func(q string) string {
				return strings.TrimSpace(h.exec(q, "sh", "-c", cli+" -u root -N -B"))
			}
			sql("create database app character set utf8mb4 collate utf8mb4_bin; create user 'app'@'%' identified by 'made by hand'; grant all privileges on app.* to 'app'@'%';")
			stored := func() string {
				return sql("select authentication_string from mysql.user where User = 'app' and Host = '%'")
			}
			before := stored()

			w := newWorkdir(t, "import_mysql")
			vars := importMysqlVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Host: "%"}
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
			if got := stored(); got != before {
				t.Fatal("the import changed the account's password")
			}

			vars.Password = "set by the step"
			w.writeAs("main.circuit.hcl", vars)
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "password_hmac") || !strings.Contains(out, "1 to change") {
				t.Fatalf("plan after adding password_wo:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := stored(); got == before {
				t.Fatal("password_wo didn't change the account's password")
			}

			other := newWorkdir(t, "import_mysql")
			vars.Host, vars.Password = "localhost", ""
			other.writeAs("main.circuit.hcl", vars)
			other.mustConn3x("init", "-no-color")
			if out, code := other.conn3x("plan", "-no-color"); code == 0 || !strings.Contains(out, "MySQL account 'app'@'localhost'") {
				t.Fatalf("plan importing app@localhost, which isn't app@%% (exit %d):\n%s", code, out)
			}
		})
	}
}
