// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type suseVars struct {
	Port, KeyFile, KnownHosts, State, Version, HoldState string
	Hold                                                 bool
}

// package on openSUSE installs with zypper, plans clean, installs a
// pinned version, holds it with a zypper lock, and removes it.
func TestPackageSUSE(t *testing.T) {
	h := startHost(t, "leap156")
	rpmq := func() string { return h.exec("", "sh", "-c", "rpm -q tree; true") }
	w := newWorkdir(t, "package_suse")
	vars := suseVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, State: "present"}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	got := rpmq()
	if !strings.HasPrefix(got, "tree-") {
		t.Fatalf("after apply: %q", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}

	// The installed version, without its release, as a pin, with tree
	// removed first so the apply installs it that way.
	vars.Version = strings.SplitN(strings.TrimPrefix(got, "tree-"), "-", 2)[0]
	h.exec("", "zypper", "-n", "-q", "remove", "tree")
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := rpmq(); !strings.HasPrefix(got, "tree-"+vars.Version) {
		t.Fatalf("after installing with version %s: %q", vars.Version, got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan with version %s:\n%s", vars.Version, out)
	}

	// A pin below the installed version downgrades, as with Ansible's
	// zypper, which adds --oldpackage. Leap has tree from its oss and its
	// update repositories, so the oss release is the older one.
	editions := h.exec("", "sh", "-c", `zypper -n -q -x search -s --match-exact -t package tree | grep -o 'edition="[^"]*"' | cut -d'"' -f2 | sort -V | head -1`)
	vars.Version = strings.TrimSpace(editions)
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := rpmq(); !strings.HasPrefix(got, "tree-"+vars.Version+".") {
		t.Fatalf("after pinning the older %s: %q", vars.Version, got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan with version %s:\n%s", vars.Version, out)
	}

	vars.State, vars.Version, vars.Hold, vars.HoldState = "latest", "", true, "held"
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan with state latest and a hold:\n%s", out)
	}
	if locks := h.exec("", "sh", "-c", "zypper -n -q locks; true"); !strings.Contains(locks, "| tree ") {
		t.Fatalf("no zypper lock: %q", locks)
	}

	// A held package can't be removed, so the hold is released first.
	vars.HoldState = "released"
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if locks := h.exec("", "sh", "-c", "zypper -n -q locks; true"); strings.Contains(locks, "| tree ") {
		t.Fatalf("lock still there after release: %q", locks)
	}
	vars.State, vars.Hold = "absent", false
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := rpmq(); !strings.Contains(got, "not installed") {
		t.Fatalf("after state absent: %q", got)
	}
}
