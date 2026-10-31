// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package sshkey

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

const (
	edA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	edB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA2WYZ1jUjx7b5r3v0xZq2tq8Yw3Wv3lH2pZk7u3Jt0b"
	// ecA is a different key type, so it lives beside an ed25519 key.
	ecA = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg="
)

func TestEditKnownHosts(t *testing.T) {
	hashed := knownhosts.HashHostname("example.com") + " "
	for name, c := range map[string]struct {
		in, host, key string
		present       bool
		want          string
	}{
		"adds to an empty file":          {"", "a.example", edA, true, "a.example " + edA + "\n"},
		"keeps the comment it was given": {"", "a.example", edA + " note", true, "a.example " + edA + " note\n"},
		"same key is no change":          {"a.example " + edA + " old\n", "a.example", edA, true, "a.example " + edA + " old\n"},
		"no change keeps a bare ending":  {"a.example " + edA, "a.example", edA, true, "a.example " + edA},
		"replaces the same type":         {"a.example " + edA + "\nb.example " + edB + "\n", "a.example", edB, true, "b.example " + edB + "\na.example " + edB + "\n"},
		"another type stays":             {"a.example " + ecA + "\n", "a.example", edA, true, "a.example " + ecA + "\na.example " + edA + "\n"},
		"port is another entry":          {"[a.example]:2222 " + edA + "\n", "a.example", edB, true, "[a.example]:2222 " + edA + "\na.example " + edB + "\n"},
		"shared line with same key":      {"a.example,10.0.0.1 " + edA + "\n", "a.example", edA, true, "a.example,10.0.0.1 " + edA + "\n"},
		"shared line keeps other names":  {"a.example,10.0.0.1 " + edA + " c\n", "a.example", edB, true, "10.0.0.1 " + edA + " c\na.example " + edB + "\n"},
		"absent removes every type":      {"# top\na.example " + edA + "\na.example " + ecA + "\nb.example " + edB + "\n", "a.example", "", false, "# top\nb.example " + edB + "\n"},
		"absent with a key takes one":    {"a.example " + edA + "\na.example " + ecA + "\n", "a.example", edA, false, "a.example " + ecA + "\n"},
		"absent from a shared line":      {"a.example,b.example " + edA + "\n", "b.example", "", false, "a.example " + edA + "\n"},
		"absent when it isn't there":     {"b.example " + edA, "a.example", "", false, "b.example " + edA},
		"absent empties the file":        {"a.example " + edA + "\n", "a.example", "", false, ""},
		"hashed entry is recognised":     {hashed + edA + "\n", "example.com", edA, true, hashed + edA + "\n"},
		"hashed entry is replaced":       {hashed + edA + "\n", "example.com", edB, true, "example.com " + edB + "\n"},
		"hashed entry is removed":        {hashed + edA + "\nb.example " + edB + "\n", "example.com", "", false, "b.example " + edB + "\n"},
		"hash for another host stays":    {hashed + edA + "\n", "other.example", "", false, hashed + edA + "\n"},
		"markers stay":                   {"@revoked a.example " + edA + "\n@cert-authority a.example " + edB + "\n", "a.example", "", false, "@revoked a.example " + edA + "\n@cert-authority a.example " + edB + "\n"},
		"patterns aren't entries":        {"*.example,!a.example " + edA + "\n", "a.example", "", false, "*.example,!a.example " + edA + "\n"},
		"case doesn't hide an entry":     {"A.example " + edA + "\n", "a.example", "", false, ""},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := EditKnownHosts(c.in, c.host, c.key, c.present)
			if err != nil || got != c.want {
				t.Fatalf("got %q, %v\nwant %q", got, err, c.want)
			}
		})
	}
}

func TestValidateKnownHost(t *testing.T) {
	for _, good := range [][2]string{{"a.example", edA}, {"[a.example]:2222", edA + " c"}, {"10.0.0.1", ""}, {"::1", ""}, {"[::1]:22", ""}} {
		if err := ValidateKnownHost(good[0], good[1]); err != nil {
			t.Errorf("%q: %v", good[0], err)
		}
	}
	for _, bad := range [][2]string{
		{"", ""}, {"A.example", ""}, {"a b", ""}, {"a,b", ""}, {"*.example", ""}, {"!a", ""}, {"|1|x|y", ""}, {"@revoked", ""}, {"[a]", ""},
		{"a", "not a key"}, {"a", "ssh-ed25519 !!!"}, {"a", "a.example " + edA}, {"a", edA + "\n" + edB},
		{"a", "ssh-rsa " + strings.Fields(edA)[1]},
	} {
		if err := ValidateKnownHost(bad[0], bad[1]); err == nil {
			t.Errorf("accepted host %q key %q", bad[0], bad[1])
		}
	}
}

var khLoc = Location{Dir: "/home/deploy/.ssh", File: "/home/deploy/.ssh/known_hosts", Owner: "deploy", Group: "deploy"}

func TestApplyKnownHostWorksAsTheUser(t *testing.T) {
	r := &recRunner{results: []ssh.Result{{}, {}}}
	if err := ApplyKnownHost(context.Background(), r, khLoc, "a.example", edA, true); err != nil {
		t.Fatal(err)
	}
	if len(r.cmds) != 2 {
		t.Fatalf("expected a read then a write, got %d commands", len(r.cmds))
	}
	for i, cmd := range r.cmds {
		if !strings.Contains(cmd, "runuser -u 'deploy'") || !strings.Contains(cmd, "known_hosts") {
			t.Fatalf("command %d did not run as the user:\n%s", i, cmd)
		}
	}
	if strings.Contains(r.cmds[1], "chown") {
		t.Fatalf("write chowns:\n%s", r.cmds[1])
	}
	if string(r.stdins[1]) != "a.example "+edA+"\n" {
		t.Fatalf("content written = %q", r.stdins[1])
	}
}

func TestApplyKnownHostLeavesASatisfiedFileAlone(t *testing.T) {
	// A step with state = "absent" must not create ~/.ssh on a user who has none.
	r := &recRunner{results: []ssh.Result{{}}}
	if err := ApplyKnownHost(context.Background(), r, khLoc, "a.example", "", false); err != nil {
		t.Fatal(err)
	}
	if len(r.cmds) != 1 {
		t.Fatalf("wrote when nothing changed:\n%s", strings.Join(r.cmds, "\n"))
	}
}

func TestApplyKnownHostReportsARefusedRead(t *testing.T) {
	r := &recRunner{results: []ssh.Result{{ExitCode: 1, Stderr: []byte("cat: Permission denied")}}}
	if err := ApplyKnownHost(context.Background(), r, khLoc, "a.example", edA, true); err == nil || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("err = %v", err)
	}
}
