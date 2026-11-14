// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package sshkey

import "testing"

const edPub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

func TestKeypairValidate(t *testing.T) {
	for _, ok := range []Keypair{{Path: "/home/deploy/.ssh/id_ed25519"}, {Path: "/k", Type: "rsa", Bits: 4096}, {Path: "/k", Type: "ecdsa", Bits: 384}} {
		if err := ok.Validate(); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
	for _, bad := range []Keypair{
		{Path: "id_ed25519"},
		{Path: "/k/"},
		{Path: "/k", Bits: 256},
		{Path: "/k", Type: "rsa", Bits: 2048},
		{Path: "/k", Type: "ecdsa", Bits: 300},
		{Path: "/k", Type: "dsa"},
		{Path: "/k", Comment: "a\nb"},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestParseKeypair(t *testing.T) {
	s, err := parseKeypair("/k", "600 deploy deploy\n"+edPub+"\n"+edPub+"  deploy@web1\n")
	if err != nil {
		t.Fatal(err)
	}
	k := Keypair{Path: "/k", Comment: "deploy@web1", Owner: "deploy"}
	if s.Type != "ed25519" || s.Bits != 256 || s.Mode != "0600" || !k.Matches(s) {
		t.Errorf("%+v doesn't match %+v", s, k)
	}
	for name, out := range map[string]string{
		"stale pub":   "600 deploy deploy\n" + edPub + "\nssh-ed25519 AAAAother deploy@web1\n",
		"no pub":      "600 deploy deploy\n" + edPub + "\n",
		"wide mode":   "644 deploy deploy\n" + edPub + "\n" + edPub + " deploy@web1\n",
		"other owner": "600 root root\n" + edPub + "\n" + edPub + " deploy@web1\n",
		"not a key":   "600 deploy deploy\n\n",
	} {
		s, err := parseKeypair("/k", out)
		if err != nil || k.Matches(s) {
			t.Errorf("%s: matched %+v, %v", name, s, err)
		}
	}
	if s, _ := parseKeypair("/k", "600 deploy deploy\n\n"); !s.Exists || s.Type != "" {
		t.Errorf("not a key: %+v", s)
	}
	if s, _ := parseKeypair("/k", ""); s.Exists {
		t.Error("nothing there, but exists")
	}
}
