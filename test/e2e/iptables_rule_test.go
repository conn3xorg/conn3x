// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type iptablesVars struct {
	Port, KeyFile, KnownHosts, Packages string
	Rules                               bool
}

// iptables_rule refuses persist on a host with nothing to load the saved
// rules at boot, then adds a rule under confirm_after and one at the top
// of INPUT, saves them where the boot loader reads them, plans clean,
// shows a rule deleted by hand as drift and adds it back, and deletes
// both, saving again, when the steps go. firewalld and ufw aren't in the
// images. A reboot can't be tested in a container, so the test checks
// the saved file instead.
func TestIPTablesRule(t *testing.T) {
	for _, c := range []struct{ image, packages, loader, saved string }{
		{"rocky10", `"iptables-nft"`, `"iptables-services"`, "/etc/sysconfig/iptables"},
		{"ubuntu2404", `"iptables"`, `"iptables-persistent"`, "/etc/iptables/rules.v4"},
	} {
		t.Run(c.image, func(t *testing.T) {
			h := startHostWith(t, c.image, "--privileged")
			rules := func() string { return h.exec("", "iptables", "-w", "-S", "INPUT") }
			saved := func() string { return h.exec("", "sh", "-c", "cat "+c.saved+" 2>&1; true") }
			const ssh = `-A INPUT -p tcp -m tcp --dport 22 -m comment --comment "it\'s \"ssh\" $HOME" -j ACCEPT` // iptables -S escapes the quote
			const replies = "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
			w := newWorkdir(t, "iptables_rule")
			vars := iptablesVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Packages: c.packages, Rules: true}
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")

			out, code := w.conn3x("apply", "-auto-approve", "-no-color")
			if code == 0 || !strings.Contains(out, "persist needs iptables-persistent (Debian, Ubuntu) or iptables-services (Red Hat family)") {
				t.Fatalf("persist without a boot loader: exit %d\n%s", code, out)
			}

			vars.Packages = c.packages + ", " + c.loader
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			got := rules()
			if i, j := strings.Index(got, replies), strings.Index(got, ssh); i < 0 || j < 0 || i > j {
				t.Fatalf("after apply, want the inserted rule first:\n%s", got)
			}
			if s := saved(); !strings.Contains(s, ssh) || !strings.Contains(s, replies) {
				t.Fatalf("%s after apply:\n%s", c.saved, s)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			h.exec("", "iptables", "-w", "-D", "INPUT", "-p", "tcp", "--dport", "22", "-m", "comment", "--comment", `it's "ssh" $HOME`, "-j", "ACCEPT")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "1 to change") || !strings.Contains(out, "conn3x_iptables_rule.ipt__ssh") {
				t.Fatalf("plan after deleting the rule by hand:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := rules(); !strings.Contains(got, ssh) {
				t.Fatalf("apply didn't add the rule back:\n%s", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after adding it back:\n%s", out)
			}

			vars.Rules = false
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := rules(); strings.Contains(got, "--dport 22") || strings.Contains(got, "ctstate") {
				t.Fatalf("removing the steps left a rule:\n%s", got)
			}
			if s := saved(); strings.Contains(s, "--dport 22") || strings.Contains(s, "ctstate") {
				t.Fatalf("%s after removing the steps:\n%s", c.saved, s)
			}
		})
	}
}
