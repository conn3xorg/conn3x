// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package sshkey

import (
	"context"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// recRunner records every command and its stdin, and replays canned results
// in order, so a test can see what Read and Apply ask the host to run.
type recRunner struct {
	results []ssh.Result
	cmds    []string
	stdins  [][]byte
}

func (r *recRunner) Run(_ context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	r.cmds = append(r.cmds, cmd)
	r.stdins = append(r.stdins, stdin)
	res := ssh.Result{}
	if len(r.results) > 0 {
		res = r.results[0]
		r.results = r.results[1:]
	}
	return res, nil
}

var loc = Location{Dir: "/home/deploy/.ssh", File: "/home/deploy/.ssh/authorized_keys", Owner: "deploy", Group: "deploy"}

func TestReadRunsAsTheUser(t *testing.T) {
	r := &recRunner{results: []ssh.Result{{Stdout: []byte(alice + "\n")}}}
	got, err := Read(context.Background(), r, loc)
	if err != nil || got != alice+"\n" {
		t.Fatalf("got %q, %v", got, err)
	}
	cmd := r.cmds[0]
	if !strings.Contains(cmd, "runuser -u 'deploy'") || !strings.Contains(cmd, `id -u -- 'deploy'`) {
		t.Fatalf("read did not drop to the user:\n%s", cmd)
	}
	if !strings.Contains(cmd, "'/home/deploy/.ssh/authorized_keys'") {
		t.Fatalf("read did not name the file:\n%s", cmd)
	}
}

func TestReadErrorsWhenTheFileCannotBeRead(t *testing.T) {
	r := &recRunner{results: []ssh.Result{{ExitCode: 1, Stderr: []byte("cat: Permission denied")}}}
	if _, err := Read(context.Background(), r, loc); err == nil || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("err = %v, want it to mention the refusal", err)
	}
}

func TestApplyWritesEditedContentAsTheUser(t *testing.T) {
	// First call is the read (empty file), second is the write.
	r := &recRunner{results: []ssh.Result{{}, {}}}
	if err := Apply(context.Background(), r, loc, alice, true); err != nil {
		t.Fatal(err)
	}
	if len(r.cmds) != 2 {
		t.Fatalf("expected a read then a write, got %d commands", len(r.cmds))
	}
	write := r.cmds[1]
	if !strings.Contains(write, "runuser -u 'deploy'") || !strings.Contains(write, "chmod 0600") || !strings.Contains(write, "mktemp") {
		t.Fatalf("write did not run as the user with a temp file:\n%s", write)
	}
	if string(r.stdins[1]) != alice+"\n" {
		t.Fatalf("content written = %q", r.stdins[1])
	}
	if strings.Contains(write, "chown") {
		t.Fatalf("write still chowns as root:\n%s", write)
	}
}

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
