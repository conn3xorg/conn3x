// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type userPasswordVars struct {
	Port, KeyFile, KnownHosts, Password string
	OnCreate                            bool
}

// checkPassword is a script that prints "match" when password opens the
// user's /etc/shadow hash, with openssl, perl or python, whichever is there.
const checkPassword = `h=$(getent shadow conn3xpw | cut -d: -f2)
if command -v openssl >/dev/null; then salt=${h#\$6\$}; salt=${salt%%\$*}; [ "$(openssl passwd -6 -salt "$salt" "$1")" = "$h" ] && echo match || echo no
elif command -v perl >/dev/null; then perl -e 'print crypt($ARGV[0], $ARGV[1]) eq $ARGV[1] ? "match" : "no"' "$1" "$h"
elif command -v python3 >/dev/null; then python3 -W ignore -c 'import crypt, sys; print("match" if crypt.crypt(sys.argv[1], sys.argv[2]) == sys.argv[2] else "no", end="")' "$1" "$h"
else echo notool; fi`

// A user step's password_wo sets the password, a hand change shows in the
// plan and the apply puts it back, and password_on_create leaves it be.
func TestUserPassword(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "user-password")
			// Where the image has no tool to check a password with, as
			// Fedora's has none, only the hashes are compared.
			opens := func(pw string) bool {
				got := strings.TrimSpace(h.exec("", "sh", "-c", checkPassword, "sh", pw))
				return got == "match" || got == "notool"
			}
			hash := func() string {
				return strings.TrimSpace(h.exec("", "sh", "-c", "getent shadow conn3xpw | cut -d: -f2"))
			}
			w.writeAs("main.circuit.hcl", userPasswordVars{h.port, h.keyFile, h.knownHosts, "first-Pass1", false})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if !opens("first-Pass1") {
				t.Fatalf("the password isn't set: %s", h.exec("", "sh", "-c", "getent shadow conn3xpw | cut -d: -f2 | cut -c1-3"))
			}
			first := hash()
			if !strings.HasPrefix(first, "$6$") {
				t.Fatalf("the hash is %q, want $6$", first[:min(3, len(first))])
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply is not empty:\n%s", out)
			}
			state := w.mustConn3x("state", "pull")
			if strings.Contains(state, "first-Pass1") || strings.Contains(state, first) {
				t.Fatal("state holds the password or its hash")
			}

			// Changed by hand: the plan sees it, and the apply puts it back.
			h.exec("hand-Pass2\n", "sh", "-c", "read p; echo \"conn3xpw:$p\" | chpasswd")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "will be updated in-place") {
				t.Fatalf("a password changed by hand isn't planned back:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if !opens("first-Pass1") || hash() != first {
				t.Fatal("the apply didn't put the password back")
			}

			// A locked account stays locked: the plan reads it as in sync,
			// and a new password is set behind the !.
			locked := func() bool { return strings.HasPrefix(hash(), "!") }
			h.exec("", "usermod", "-L", "conn3xpw")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("a locked account plans a change:\n%s", out)
			}
			w.writeAs("main.circuit.hcl", userPasswordVars{h.port, h.keyFile, h.knownHosts, "locked-Pass4", false})
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if !locked() {
				t.Fatal("setting a password unlocked a locked account")
			}
			h.exec("", "usermod", "-U", "conn3xpw")
			if !opens("locked-Pass4") {
				t.Fatal("the password set while locked doesn't open after unlocking")
			}
			w.writeAs("main.circuit.hcl", userPasswordVars{h.port, h.keyFile, h.knownHosts, "first-Pass1", false})
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			// A new password plans a change; with password_on_create it doesn't.
			w.writeAs("main.circuit.hcl", userPasswordVars{h.port, h.keyFile, h.knownHosts, "second-Pass3", true})
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if !opens("first-Pass1") || hash() != first {
				t.Fatal("password_on_create changed an existing user's password")
			}
			w.writeAs("main.circuit.hcl", userPasswordVars{h.port, h.keyFile, h.knownHosts, "second-Pass3", false})
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if !opens("second-Pass3") || hash() == first {
				t.Fatal("a new password_wo wasn't set")
			}
		})
	}
}

// password_hash_wo sets a hash made elsewhere as it is, plans clean, and a
// hand change shows in the plan.
func TestUserPasswordHash(t *testing.T) {
	h := startHost(t, "debian13")
	hash := strings.TrimSpace(h.exec("", "perl", "-e", `print crypt("hash-Pass1", '$6$conn3xsalt$')`))
	if !strings.HasPrefix(hash, "$6$conn3xsalt$") {
		t.Fatalf("perl made %q", hash)
	}
	shadow := func() string {
		return strings.TrimSpace(h.exec("", "sh", "-c", "getent shadow conn3xpw | cut -d: -f2"))
	}
	w := newWorkdir(t, "user-password-hash")
	w.writeAs("main.circuit.hcl", userPasswordVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Password: hash})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := shadow(); got != hash {
		t.Fatalf("shadow holds %q, want the given hash", got)
	}
	if got := strings.TrimSpace(h.exec("", "sh", "-c", checkPassword, "sh", "hash-Pass1")); got != "match" {
		t.Fatalf("the password doesn't open the hash: %s", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}
	if strings.Contains(w.mustConn3x("state", "pull"), hash) {
		t.Fatal("state holds the hash")
	}
	h.exec("", "sh", "-c", "echo 'conn3xpw:other-Pass2' | chpasswd")
	if out := w.mustConn3x("plan", "-no-color"); strings.Contains(out, "No changes.") {
		t.Fatalf("a hand change plans nothing:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := shadow(); got != hash {
		t.Fatalf("after putting it back, shadow holds %q", got)
	}
}
