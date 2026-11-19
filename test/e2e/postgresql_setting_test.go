// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// TestPostgreSQLSetting sets a setting taken on a reload, one given in
// another unit and rounded, one that waits for a restart, and a list;
// plans clean, with the restart still pending; puts back a change made by
// hand; and resets the setting with on_remove = "delete" on destroy.
func TestPostgreSQLSetting(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			psqlIn := installPostgreSQL(t, h, image)
			psql := func(sql string) string { return psqlIn("postgres", sql) }

			w := newWorkdir(t, "postgresql_setting")
			w.writeAs("main.circuit.hcl", circuitVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := psql("show work_mem"); got != "64MB" {
				t.Fatalf("work_mem: %q", got)
			}
			if got := psql("select setting from pg_settings where name = 'effective_cache_size'"); got != "12" {
				t.Fatalf("effective_cache_size in pages: %q", got)
			}
			if got := psql("select pending_restart from pg_settings where name = 'shared_buffers'"); got != "t" {
				t.Fatalf("shared_buffers pending_restart: %q", got)
			}
			if got := psql("show search_path"); got != `"$user", public, reporting` {
				t.Fatalf("search_path: %q", got)
			}
			if out := w.mustConn3x("show", "-json"); !strings.Contains(out, `"restart_required":true`) {
				t.Fatalf("no restart_required in state:\n%s", out)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			// A change by hand shows in the plan, and the apply puts it back.
			psql("alter system set work_mem = '1MB'")
			psql("select pg_reload_conf()")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "work_mem") {
				t.Fatalf("a hand change isn't planned back:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := psql("show work_mem"); got != "64MB" {
				t.Fatalf("work_mem after the second apply: %q", got)
			}

			w.mustConn3x("destroy", "-auto-approve", "-no-color")
			if got := psql("select count(*) from pg_file_settings where name = 'work_mem' and sourcefile like '%postgresql.auto.conf'"); got != "0" {
				t.Fatalf("work_mem still in postgresql.auto.conf after destroy: %q", got)
			}
			if got := psql("select count(*) from pg_file_settings where name = 'search_path' and sourcefile like '%postgresql.auto.conf'"); got != "1" {
				t.Fatalf("search_path, forgotten, left postgresql.auto.conf: %q", got)
			}
		})
	}
}
