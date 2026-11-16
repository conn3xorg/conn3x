// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package sshkey

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func authorized(t *testing.T, key any) string {
	t.Helper()
	pub, err := gossh.NewPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(pub)))
}

func TestKeyKind(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 1024) // the size only has to read back
	if err != nil {
		t.Fatal(err)
	}
	for want, line := range map[string]string{"ecdsa 384": authorized(t, &ec.PublicKey), "rsa 1024": authorized(t, &rk.PublicKey)} {
		s, err := parseKeypair("/k", "600 a b\n"+line+"\n")
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%s %d", s.Type, s.Bits); got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	}
	if _, err := parseKeypair("/k", "weird\n"); err == nil || !strings.Contains(err.Error(), `unexpected stat output "weird"`) {
		t.Errorf("bad stat: %v", err)
	}
}

func TestApplyKeypair(t *testing.T) {
	ctx := context.Background()
	k := Keypair{Path: "/home/deploy/.ssh/id_ed25519", Comment: "deploy@web1", Owner: "deploy"}
	good := ssh.Result{Stdout: []byte("600 deploy deploy\n" + edPub + "\n" + edPub + " deploy@web1\n")}

	r := &recRunner{results: []ssh.Result{{}, {}, good}}
	got, err := ApplyKeypair(ctx, r, k)
	if err != nil || got.Type != "ed25519" {
		t.Fatalf("missing key: %+v, %v", got, err)
	}
	if !strings.Contains(r.cmds[1], "ssh-keygen -q -t ed25519 -b 256 -N ") {
		t.Errorf("a missing key wasn't made:\n%s", r.cmds[1])
	}

	// A key of the right kind with the wrong mode is copied, not made anew.
	r = &recRunner{results: []ssh.Result{{Stdout: []byte("644 deploy deploy\n" + edPub + "\n")}, {}, good}}
	if _, err := ApplyKeypair(ctx, r, k); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.cmds[1], "ssh-keygen -q") || !strings.Contains(r.cmds[1], `cp -- "$p" "$d/key"`) {
		t.Errorf("a key of the right kind was replaced:\n%s", r.cmds[1])
	}

	r = &recRunner{results: []ssh.Result{{Stdout: []byte("600 deploy deploy\n\n")}}}
	if _, err := ApplyKeypair(ctx, r, k); err == nil || !strings.Contains(err.Error(), "isn't an unencrypted SSH key") || len(r.cmds) != 1 {
		t.Errorf("not a key: %v after %d commands", err, len(r.cmds))
	}
	r = &recRunner{results: []ssh.Result{{}, {}, {Stdout: []byte("644 root root\n" + edPub + "\n")}}}
	if _, err := ApplyKeypair(ctx, r, k); err == nil || err.Error() != "/home/deploy/.ssh/id_ed25519 doesn't hold the key asked for after writing it: found a ed25519 key, mode 0644, owner root:root" {
		t.Errorf("read back: %v", err)
	}
	r = &recRunner{results: []ssh.Result{{}, {}, {}}}
	if _, err := ApplyKeypair(ctx, r, k); err == nil || !strings.Contains(err.Error(), "found a unreadable key") {
		t.Errorf("nothing read back: %v", err)
	}
	r = &recRunner{results: []ssh.Result{{}, {ExitCode: 1, Stderr: []byte("ssh-keygen isn't installed")}}}
	if _, err := ApplyKeypair(ctx, r, k); err == nil || err.Error() != "ssh-keygen isn't installed" {
		t.Errorf("write: %v", err)
	}
	r = &recRunner{results: []ssh.Result{{}, {}, {ExitCode: 1, Stderr: []byte("gone")}}}
	if _, err := ApplyKeypair(ctx, r, k); err == nil || err.Error() != "gone" {
		t.Errorf("read back error: %v", err)
	}
	r = &recRunner{results: []ssh.Result{{ExitCode: 1, Stderr: []byte("/k is not a regular file")}}}
	if _, err := ApplyKeypair(ctx, r, k); err == nil || err.Error() != "/k is not a regular file" {
		t.Errorf("read: %v", err)
	}
	r = &recRunner{}
	if _, err := ApplyKeypair(ctx, r, Keypair{Path: "rel"}); err == nil || len(r.cmds) != 0 {
		t.Errorf("an invalid keypair reached the host: %v", err)
	}
}

func TestDeleteKeypair(t *testing.T) {
	ctx := context.Background()
	r := &recRunner{}
	if err := DeleteKeypair(ctx, r, "/k"); err != nil || len(r.cmds) != 2 || !strings.Contains(r.cmds[1], "'/k.pub'") {
		t.Errorf("delete: %v, ran %d", err, len(r.cmds))
	}
	r = &recRunner{results: []ssh.Result{{ExitCode: 1, Stderr: []byte("denied")}}}
	if err := DeleteKeypair(ctx, r, "/k"); err == nil || err.Error() != "denied" || len(r.cmds) != 1 {
		t.Errorf("first delete fails: %v, ran %d", err, len(r.cmds))
	}
	if err := check(ssh.Result{}, errors.New("down")); err == nil || err.Error() != "down" {
		t.Errorf("check: %v", err)
	}
}
