// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type firewalldRichVars struct {
	Port, KeyFile, KnownHosts string
	Rule                      bool
}

// A rich rule opens a port to one network, in the running firewall and
// the permanent configuration. firewalld spells it back with quotes, and
// the plan stays clean all the same. Removing the step takes it out of
// both.
func TestFirewalldRichRule(t *testing.T) {
	h := startHostWith(t, "rocky10", "--privileged")
	w := newWorkdir(t, "firewalld_rich")
	vars := firewalldRichVars{h.port, h.keyFile, h.knownHosts, false}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	h.exec("", "systemctl", "enable", "--now", "firewalld")

	const listed = `rule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="tcp" accept`
	rules := func(perm string) string {
		args := []string{"firewall-cmd", "--zone=public", "--list-rich-rules"}
		if perm != "" {
			args = append(args, perm)
		}
		return strings.TrimSpace(h.exec("", args...))
	}

	vars.Rule = true
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got, perm := rules(""), rules("--permanent"); got != listed || perm != listed {
		t.Fatalf("after adding: running %q, permanent %q", got, perm)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan with the rule spelled back differently:\n%s", out)
	}

	// Taken out of the running firewall by hand, it plans a change.
	h.exec("", "firewall-cmd", "--zone=public", "--remove-rich-rule="+listed)
	if out := w.mustConn3x("plan", "-no-color"); strings.Contains(out, "No changes.") {
		t.Fatalf("a rule removed by hand plans nothing:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")

	vars.Rule = false
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got, perm := rules(""), rules("--permanent"); got != "" || perm != "" {
		t.Fatalf("after removing the step: running %q, permanent %q", got, perm)
	}
}
