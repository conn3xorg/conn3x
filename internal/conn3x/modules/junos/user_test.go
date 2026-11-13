// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package junos

import (
	"slices"
	"testing"
)

const userConfig = `set system login user alice uid 2001
set system login user alice class operator
set system login user alice authentication encrypted-password "$6$old$hash"
set system login user alice authentication ssh-ed25519 "ssh-ed25519 AAAAold alice@old"
set system login user ops class super-user
`

func TestUserCommands(t *testing.T) {
	u := User{
		Name: "alice", Class: "super-user", WantSecret: true, Secret: "$6$new$hash",
		SecretIs: func(h string) bool { return h == "$6$new$hash" },
		SSHKeys:  []string{"ssh-ed25519 AAAAnew alice@laptop", "ecdsa-sha2-nistp256 AAAAec alice@phone"},
	}
	want := []string{
		"delete system login user alice class",
		"set system login user alice class super-user",
		"delete system login user alice authentication encrypted-password",
		`set system login user alice authentication encrypted-password "$6$new$hash"`,
		`delete system login user alice authentication ssh-ed25519 "ssh-ed25519 AAAAold alice@old"`,
		`set system login user alice authentication ssh-ed25519 "ssh-ed25519 AAAAnew alice@laptop"`,
		`set system login user alice authentication ssh-ecdsa "ecdsa-sha2-nistp256 AAAAec alice@phone"`,
	}
	if got := u.Commands(userConfig); !slices.Equal(got, want) {
		t.Errorf("Commands:\n%q\nwant\n%q", got, want)
	}
	if !u.InSync(WithLines(userConfig, want)) {
		t.Error("not in sync once its commands are in")
	}
	// Without the HMAC key a read can't tell which password it is: any counts.
	blind := User{Name: "alice", Class: "operator", WantSecret: true}
	if !blind.InSync(userConfig) {
		t.Error("a password the read can't check counted as wrong")
	}
	if got := (User{Name: "bob", Class: "read-only"}).Commands(userConfig); !slices.Equal(got, []string{"set system login user bob class read-only"}) {
		t.Errorf("new account: %q", got)
	}
}

func TestUserRemoveAndGuard(t *testing.T) {
	if got := (User{Name: "alice", Class: "operator"}).RemoveCommands(userConfig); !slices.Equal(got, []string{"delete system login user alice"}) {
		t.Errorf("RemoveCommands = %q", got)
	}
	if (User{Name: "ops", Class: "operator"}).Guard("ops") == nil {
		t.Error("demoted the login account")
	}
	if (User{Name: "alice", Class: "operator"}).Guard("ops") != nil {
		t.Error("guarded another account")
	}
	for _, bad := range []User{{Name: "root", Class: "super-user"}, {Name: "a b", Class: "operator"}, {Name: "x", Class: ""}, {Name: "x", Class: "operator", SSHKeys: []string{"not a key"}}} {
		if bad.Validate() == nil {
			t.Errorf("%+v passed", bad)
		}
	}
}
