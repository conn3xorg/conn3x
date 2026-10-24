// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package sshkey

import "testing"

const (
	alice  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl alice@laptop"
	alice2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl alice@other"
	bob    = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA2WYZ1jUjx7b5r3v0xZq2tq8Yw3Wv3lH2pZk7u3Jt0b bob"
)

func TestEditAddsKeyOnce(t *testing.T) {
	got, err := Edit("", alice, true)
	if err != nil || got != alice+"\n" {
		t.Fatalf("got %q, %v", got, err)
	}
	again, _ := Edit(got, alice2, true)
	if again != got {
		t.Fatalf("same key with a different comment added again: %q", again)
	}
	both, _ := Edit(got, bob, true)
	if both != alice+"\n"+bob+"\n" {
		t.Fatalf("got %q", both)
	}
}

func TestEditKeepsOptionsAndOtherLines(t *testing.T) {
	in := "# managed elsewhere\nfrom=\"10.0.0.0/8\" " + bob + "\n"
	got, _ := Edit(in, bob, true)
	if got != in {
		t.Fatalf("existing key with options changed: %q", got)
	}
}

func TestEditRemovesKey(t *testing.T) {
	in := alice + "\n" + bob + "\n"
	got, _ := Edit(in, alice2, false)
	if got != bob+"\n" {
		t.Fatalf("got %q", got)
	}
}

func TestEditRejectsInvalidKeys(t *testing.T) {
	for _, bad := range []string{"", "not a key", "ssh-ed25519 !!!", "ssh-ed25519 AAAA x\nssh-rsa AAAA y"} {
		if _, err := Edit("", bad, true); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
