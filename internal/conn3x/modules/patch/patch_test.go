// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package patch

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func TestValidate(t *testing.T) {
	for _, good := range []Patch{
		{Content: "x", Dest: "/etc/app.conf", State: Present},
		{Src: "/tmp/fix.patch", Basedir: "/opt/app", Strip: 1, State: Absent},
	} {
		if err := good.Validate(); err != nil {
			t.Errorf("%+v: %v", good, err)
		}
	}
	for _, bad := range []Patch{
		{Dest: "/a", State: Present},
		{Content: "x", Src: "/p", Dest: "/a", State: Present},
		{Content: "x", State: Present},
		{Content: "x", Dest: "/a", Basedir: "/b", State: Present},
		{Content: "x", Dest: "etc/app.conf", State: Present},
		{Content: "x", Basedir: "/a\nb", State: Present},
		{Src: "fix.patch", Dest: "/a", State: Present},
		{Content: "x", Dest: "/a", Strip: -1, State: Present},
		{Content: "x", Dest: "/a", State: "reverted"},
		{Content: "x", Dest: "/a"},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v: no error", bad)
		}
	}
}

// Every value reaches the shell as one quoted word.
func TestCommandQuotes(t *testing.T) {
	p := Patch{Src: "/srv/it's $x.patch", Basedir: "/opt/my app", Strip: 1, IgnoreWhitespace: true, Binary: true}
	want := `patch --batch --forward --reject-file=- --no-backup-if-mismatch -p1 --ignore-whitespace --binary -d '/opt/my app' -i '/srv/it'\''s $x.patch' --dry-run --reverse`
	if got := p.command("--dry-run", "--reverse"); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	p = Patch{Content: "x", Dest: "/etc/a b.conf"}
	if got, want := p.command(), `patch --batch --forward --reject-file=- --no-backup-if-mismatch -p0 '/etc/a b.conf'`; got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestClassify(t *testing.T) {
	for _, c := range []struct {
		reverse, forward int
		want             Status
	}{
		{0, 1, Applied}, {0, 0, Applied}, {1, 0, NotApplied}, {1, 1, Conflict}, {2, 2, Conflict}, {1, 2, Conflict},
	} {
		if got := classify(c.reverse, c.forward); got != c.want {
			t.Errorf("reverse %d forward %d: %s, want %s", c.reverse, c.forward, got, c.want)
		}
	}
	if !InSync(Present, Applied) || !InSync(Absent, NotApplied) || InSync(Present, NotApplied) || InSync(Absent, Applied) || InSync(Present, Conflict) || InSync(Absent, Conflict) {
		t.Error("InSync")
	}
}

// host answers the reverse and forward dry runs with the given exit
// statuses, and records every other patch it runs.
type host struct {
	reverse, forward int
	missing          bool // dest doesn't exist
	ran              []string
	stdin            []string
}

func (h *host) Run(_ context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	if cmd == "test -e '/etc/app.conf'" {
		return ssh.Result{ExitCode: map[bool]int{true: 1, false: 0}[h.missing]}, nil
	}
	h.stdin = append(h.stdin, string(stdin))
	switch {
	case strings.HasSuffix(cmd, "--dry-run --reverse '/etc/app.conf'"):
		return ssh.Result{ExitCode: h.reverse}, nil
	case strings.HasSuffix(cmd, "--dry-run '/etc/app.conf'"):
		return ssh.Result{ExitCode: h.forward, Stdout: []byte("checking file /etc/app.conf\nHunk #1 FAILED at 3.\n")}, nil
	}
	h.ran = append(h.ran, strings.TrimPrefix(cmd, "patch --batch --forward --reject-file=- --no-backup-if-mismatch -p0 "))
	return ssh.Result{}, nil
}

func TestApply(t *testing.T) {
	for _, c := range []struct {
		state            State
		reverse, forward int
		want             []string
	}{
		{Present, 1, 0, []string{"'/etc/app.conf'"}},
		{Present, 0, 1, nil},
		{Absent, 0, 1, []string{"--reverse '/etc/app.conf'"}},
		{Absent, 1, 0, nil},
	} {
		h := &host{reverse: c.reverse, forward: c.forward}
		if err := Apply(context.Background(), h, Patch{Content: "the patch", Dest: "/etc/app.conf", State: c.state}); err != nil {
			t.Errorf("%s %d/%d: %v", c.state, c.reverse, c.forward, err)
		}
		if !reflect.DeepEqual(h.ran, c.want) {
			t.Errorf("%s %d/%d: ran %q, want %q", c.state, c.reverse, c.forward, h.ran, c.want)
		}
		for _, in := range h.stdin {
			if in != "the patch" {
				t.Errorf("stdin %q", in)
			}
		}
	}
}

// Neither direction applies: Apply refuses, says why, and touches nothing.
func TestApplyConflict(t *testing.T) {
	for _, st := range []State{Present, Absent} {
		h := &host{reverse: 1, forward: 1}
		err := Apply(context.Background(), h, Patch{Content: "x", Dest: "/etc/app.conf", State: st})
		if err == nil || !strings.Contains(err.Error(), "has moved on") || !strings.Contains(err.Error(), "Hunk #1 FAILED") {
			t.Errorf("%s: %v", st, err)
		}
		if len(h.ran) != 0 {
			t.Errorf("%s: ran %q", st, h.ran)
		}
	}
}

func TestMissingPatch(t *testing.T) {
	r := runFunc(func(string) ssh.Result { return ssh.Result{ExitCode: 127} })
	if _, _, err := Check(context.Background(), r, Patch{Content: "x", Dest: "/a"}); err == nil || !strings.Contains(err.Error(), "install the patch package") {
		t.Errorf("got %v", err)
	}
}

type runFunc func(string) ssh.Result

func (f runFunc) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) { return f(cmd), nil }

// A dest that isn't there reads as a conflict to patch; Apply says the
// file is missing instead of that it moved on.
func TestApplyMissingDest(t *testing.T) {
	h := &host{reverse: 1, forward: 1, missing: true}
	err := Apply(context.Background(), h, Patch{Content: "x", Dest: "/etc/app.conf", State: Present})
	if err == nil || !strings.Contains(err.Error(), "/etc/app.conf doesn't exist") || strings.Contains(err.Error(), "moved on") {
		t.Errorf("got %v", err)
	}
	if len(h.ran) != 0 {
		t.Errorf("ran %q", h.ran)
	}
}
