// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package eos

import (
	"slices"
	"strings"
	"testing"
)

const usersRunning = `! Command: show running-config
username admin privilege 15 role network-admin nopassword
username admin ssh-key ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGUr c3x-lab
username bob privilege 15 role network-admin secret sha512 $6$opl$Eam
username bobby role network-operator nopassword
!
`

func TestUserCommands(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPqY carol@laptop"
	empty := ""
	for name, tc := range map[string]struct {
		u    User
		want []string // nil: in sync
	}{
		"in sync":             {User{Name: "bob", Privilege: 15, Role: "network-admin", WantSecret: true}, nil},
		"not bobby":           {User{Name: "bob", Privilege: -1, Role: "network-admin"}, nil},
		"new, no password":    {User{Name: "carol", Privilege: -1, Role: "network-operator", SSHKey: &key}, []string{"username carol role network-operator nopassword", "username carol ssh-key " + key}},
		"new, password":       {User{Name: "dave", Privilege: 5, WantSecret: true, Secret: "s3cret"}, []string{"username dave privilege 5 secret s3cret"}},
		"demote keeps secret": {User{Name: "bob", Privilege: 1, Role: "network-operator", WantSecret: true, Secret: "x"}, []string{"username bob privilege 1 role network-operator"}},
		"rotate":              {User{Name: "bob", Privilege: -1, WantSecret: true, Secret: "new", Rotate: true}, []string{"username bob secret new"}},
		"first password":      {User{Name: "bobby", Privilege: -1, WantSecret: true, Secret: "pw"}, []string{"username bobby secret pw"}},
		"drop the key":        {User{Name: "admin", Privilege: -1, SSHKey: &empty}, []string{"no username admin ssh-key"}},
	} {
		got := tc.u.Commands(usersRunning)
		if tc.want == nil {
			if !tc.u.InSync(usersRunning) {
				t.Errorf("%s: not in sync, commands %q", name, got)
			}
			continue
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: commands %q, want %q", name, got, tc.want)
		}
	}
	if (User{Name: "bob", Privilege: -1, WantSecret: true, Rotate: true}).InSync(usersRunning) != true {
		t.Error("a read can't see a rotation, so a set secret is in sync")
	}
	if got := (User{Name: "bob"}).RemoveCommands(usersRunning); !slices.Equal(got, []string{"no username bob"}) {
		t.Errorf("remove: %q", got)
	}
	if (User{Name: "zed"}).RemoveCommands(usersRunning) != nil {
		t.Error("removing an account that isn't there sends nothing")
	}
}

func TestUserValidateAndGuard(t *testing.T) {
	bad := "not a key"
	for want, u := range map[string]User{
		"not a user name":     {Name: "two words", Privilege: -1},
		"privilege must be":   {Name: "a", Privilege: 16},
		"not a role name":     {Name: "a", Privilege: -1, Role: "net admin"},
		"can't hold spaces":   {Name: "a", Privilege: -1, Secret: "two words"},
		"one public key line": {Name: "a", Privilege: -1, SSHKey: &bad},
	} {
		if err := u.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: err = %v, want %q", u, err, want)
		}
	}
	if err := (User{Name: "admin", Privilege: 1}).Guard("admin"); err == nil {
		t.Error("demoting the login user wasn't refused")
	}
	if err := (User{Name: "admin", Privilege: -1, Role: "network-operator"}).Guard("admin"); err == nil {
		t.Error("changing the login user's role wasn't refused")
	}
	if err := (User{Name: "bob", Privilege: 1}).Guard("admin"); err != nil {
		t.Error(err)
	}
}
