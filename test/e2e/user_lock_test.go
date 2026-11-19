// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type userLockVars struct {
	Port, KeyFile, KnownHosts, Hash, Expires string
	Locked                                   bool
}

// Offboarding: lock a contractor's account and give it a last day. A hand
// unlock or a moved date plans a change back, and an expiry can be cleared.
func TestUserLockExpires(t *testing.T) {
	h := startHost(t, "debian13")
	// A fixed SHA-512 hash, so the test needs no hashing tool.
	hash := strings.TrimSpace(h.exec("", "sh", "-c", `perl -e 'print crypt("Contract-Pass-1", q($6$conn3xsalt$))'`))
	shadow := func() string {
		return strings.TrimSpace(h.exec("", "sh", "-c", "getent shadow conn3xc | cut -d: -f2,8"))
	}
	w := newWorkdir(t, "user-lock")
	write := func(locked bool, expires string) {
		w.writeAs("main.circuit.hcl", userLockVars{h.port, h.keyFile, h.knownHosts, hash, expires, locked})
	}
	clean := func(when string) {
		t.Helper()
		if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
			t.Fatalf("plan %s:\n%s", when, out)
		}
	}

	write(true, "2026-12-31")
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := shadow(); got != "!"+hash+":20818" {
		t.Fatalf("after locking with a last day: %q", got)
	}
	clean("after locking")

	h.exec("", "usermod", "-U", "-e", "", "conn3xc")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "locked") || !strings.Contains(out, "expires") {
		t.Fatalf("a hand unlock and cleared expiry plan nothing:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := shadow(); got != "!"+hash+":20818" {
		t.Fatalf("after putting them back: %q", got)
	}

	write(false, "")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := shadow(); got != hash+":" {
		t.Fatalf("after unlocking and clearing the expiry: %q", got)
	}
	clean("after unlocking")
}
