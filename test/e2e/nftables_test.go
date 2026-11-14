// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type nftVars struct {
	Port, KeyFile, KnownHosts, Port2 string
	Confirm                          bool
}

// nftables owns one table: it loads it in one transaction, sees a rule
// added by hand, changes it under confirm_after, refuses a body nft
// refuses with nothing changed, and deletes the table and its boot unit.
func TestNftables(t *testing.T) {
	for _, image := range []string{"debian13", "rocky10"} {
		t.Run(image, func(t *testing.T) {
			h := startHostWith(t, image, "--privileged")
			list := func() string { return h.exec("", "sh", "-c", "nft list table inet conn3x 2>&1; true") }
			w := newWorkdir(t, "nftables")
			vars := nftVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Port2: "8080"}
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := list(); !strings.Contains(got, "tcp dport 8080 accept") {
				t.Fatalf("after apply:\n%s", got)
			}
			if got := h.exec("", "sh", "-c", "systemctl is-enabled conn3x-nft-inet-conn3x.service"); strings.TrimSpace(got) != "enabled" {
				t.Errorf("boot unit: %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			h.exec("", "nft", "add", "rule", "inet", "conn3x", "input", "tcp", "dport", "9999", "drop")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "1 to change") {
				t.Fatalf("a rule added by hand should be drift:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := list(); strings.Contains(got, "9999") {
				t.Fatalf("apply left the rule added by hand:\n%s", got)
			}

			// A change under confirm_after: Conn3x reconnects, so it stays.
			vars.Port2, vars.Confirm = "8443", true
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := list(); !strings.Contains(got, "8443") || strings.Contains(got, "8080") {
				t.Fatalf("after the confirmed change:\n%s", got)
			}

			// nft refuses the body: the error says why, and the table stays.
			vars.Port2 = "not-a-port"
			w.writeAs("main.circuit.hcl", vars)
			if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code == 0 || !strings.Contains(out, "nft refused the table") {
				t.Fatalf("a bad body (exit %d):\n%s", code, out)
			}
			if got := list(); !strings.Contains(got, "8443") {
				t.Fatalf("a refused body changed the table:\n%s", got)
			}

			vars.Port2 = "8443"
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("destroy", "-auto-approve", "-no-color", "-target", "conn3x_nftables.fw__table")
			if got := list(); !strings.Contains(got, "No such file") && !strings.Contains(got, "does not exist") && strings.Contains(got, "table inet conn3x") {
				t.Fatalf("destroy left the table:\n%s", got)
			}
			if got := h.exec("", "sh", "-c", "ls /etc/systemd/system/conn3x-nft-inet-conn3x.service 2>&1; true"); !strings.Contains(got, "No such file") {
				t.Errorf("destroy left the unit: %s", got)
			}
		})
	}
}
