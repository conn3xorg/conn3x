// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package facts

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// answer replies to every command with res, or err.
type answer struct {
	res ssh.Result
	err error
}

func (a answer) Run(context.Context, string, []byte) (ssh.Result, error) { return a.res, a.err }

func TestGatherHost(t *testing.T) {
	ctx := context.Background()
	out := "id=fedora\nversion=41\nlike=\narch=x86_64\ncpus=4\nmemory_kb=2097152\nipv4=10.0.0.5\n"
	f, err := Gather(ctx, answer{res: ssh.Result{Stdout: []byte(out)}})
	if err != nil || f.Family != "redhat" || f.CPUs != 4 || f.MemoryMB != 2048 || f.IPv4 != "10.0.0.5" {
		t.Errorf("got %+v, %v", f, err)
	}
	if _, err := Gather(ctx, answer{res: ssh.Result{ExitCode: 1, Stderr: []byte("nproc: not found\n")}}); err == nil || err.Error() != "reading host facts: nproc: not found" {
		t.Errorf("failed script: %v", err)
	}
	if _, err := Gather(ctx, answer{err: errors.New("lost")}); err == nil || err.Error() != "lost" {
		t.Errorf("runner error: %v", err)
	}
}

// Each Red Hat id is the redhat family on its own, without ID_LIKE.
func TestParseRedHatIDs(t *testing.T) {
	for _, id := range []string{"rhel", "centos", "almalinux", "rocky"} {
		f, err := parse("id=" + id + "\nversion=9\narch=x86_64\ncpus=1\nmemory_kb=1024\n")
		if err != nil || f.Family != "redhat" {
			t.Errorf("%s: %+v, %v", id, f, err)
		}
	}
	for in, want := range map[string]string{
		"id=debian\nversion=12\narch=x86_64\ncpus=x\nmemory_kb=1\n":    `reading the CPU count "x"`,
		"id=debian\nversion=12\narch=x86_64\ncpus=1\nmemory_kb=lots\n": `reading the memory size "lots"`,
	} {
		if _, err := parse(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", in, err, want)
		}
	}
}

func TestLocalFromHost(t *testing.T) {
	ctx := context.Background()
	b64 := base64.StdEncoding.EncodeToString
	// A .fact file in INI with a section named twice merges into one.
	ini := "[web]\nport = 80\n[web]\nhost: a\n"
	out := "/etc/conn3x/facts.d/app.fact\n" + b64([]byte(ini)) + "\n"
	got, err := Local(ctx, answer{res: ssh.Result{Stdout: []byte(out)}})
	if err != nil || string(got["app"]) != `{"web":{"host":"a","port":"80"}}` {
		t.Errorf("got %q, %v", got["app"], err)
	}
	if _, err := Local(ctx, answer{res: ssh.Result{ExitCode: 2, Stderr: []byte("denied")}}); err == nil || err.Error() != "reading local facts: denied" {
		t.Errorf("failed script: %v", err)
	}
	if _, err := Local(ctx, answer{err: errors.New("lost")}); err == nil || err.Error() != "lost" {
		t.Errorf("runner error: %v", err)
	}
	if _, err := Local(ctx, answer{res: ssh.Result{Stdout: []byte("/x/a.fact\n%%%\n")}}); err == nil || !strings.Contains(err.Error(), "local fact file /x/a.fact: illegal base64") {
		t.Errorf("bad base64: %v", err)
	}
}
