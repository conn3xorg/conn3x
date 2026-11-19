// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package htpasswd

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestEdit(t *testing.T) {
	const file = "alice:$apr1$x$y\nbob:$2y$05$z\n"
	if got := Set(file, "bob", "H"); got != "alice:$apr1$x$y\nbob:H\n" {
		t.Errorf("change: %q", got)
	}
	if got := Set(file, "carol", "H"); got != file+"carol:H\n" {
		t.Errorf("add: %q", got)
	}
	if got := Set("", "carol", "H"); got != "carol:H\n" {
		t.Errorf("new file: %q", got)
	}
	if got := Set("alice:A", "bob", "H"); got != "alice:A\nbob:H\n" {
		t.Errorf("no final newline: %q", got)
	}
	if got := Remove(file, "alice"); got != "bob:$2y$05$z\n" {
		t.Errorf("remove: %q", got)
	}
	if got := Remove(file, "nobody"); got != file {
		t.Errorf("remove a missing user: %q", got)
	}
	if h, ok := Find(file, "bob"); !ok || h != "$2y$05$z" {
		t.Errorf("find: %q %v", h, ok)
	}
	if _, ok := Find(file, "bo"); ok {
		t.Error("found a prefix of a name")
	}
}

func TestHash(t *testing.T) {
	h, err := Hash("s3cret pw")
	if err != nil || !strings.HasPrefix(h, "$2y$10$") {
		t.Fatalf("%q %v", h, err)
	}
	if bcrypt.CompareHashAndPassword([]byte(h), []byte("s3cret pw")) != nil || bcrypt.CompareHashAndPassword([]byte(h), []byte("other")) == nil {
		t.Error("the hash doesn't check out")
	}
	for _, pw := range []string{"", strings.Repeat("x", 73)} {
		if _, err := Hash(pw); err == nil {
			t.Errorf("%d bytes accepted", len(pw))
		}
	}
	for _, n := range []string{"", "a:b", "a\nb"} {
		if ValidateName(n) == nil {
			t.Errorf("name %q accepted", n)
		}
	}
}

func TestRename(t *testing.T) {
	const file = "alice:A\nadmin:OLD\nbob:B\n"
	if got := Rename(file, "admin", "ops", "NEW"); got != "alice:A\nops:NEW\nbob:B\n" {
		t.Errorf("rename in place: %q", got)
	}
	if got := Rename(file, "admin", "bob", "NEW"); got != "alice:A\nbob:NEW\n" {
		t.Errorf("rename onto an existing user: %q", got)
	}
	if got := Rename(file, "gone", "ops", "NEW"); got != file+"ops:NEW\n" {
		t.Errorf("old name missing: %q", got)
	}
}
