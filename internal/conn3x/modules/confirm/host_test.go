// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package confirm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// host answers each run with the next result and records the commands
// and what each was given on stdin.
type host struct {
	res   []ssh.Result
	err   error
	cmds  []string
	stdin []string
}

func (h *host) Run(_ context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	h.cmds, h.stdin = append(h.cmds, cmd), append(h.stdin, string(stdin))
	if h.err != nil {
		return ssh.Result{}, h.err
	}
	r := h.res[0]
	h.res = h.res[1:]
	return r, nil
}

func fail(code int, stderr string) ssh.Result {
	return ssh.Result{ExitCode: code, Stderr: []byte(stderr)}
}

var g = Guard{ID: "abc", Files: []string{"/etc/ssh/sshd_config"}, After: 90 * time.Second}

func TestArm(t *testing.T) {
	ctx := context.Background()
	h := &host{res: []ssh.Result{{}, {}}}
	if err := Arm(ctx, h, g); err != nil {
		t.Fatal(err)
	}
	if len(h.cmds) != 2 || !strings.Contains(h.cmds[1], "--on-active=90s") || !strings.Contains(h.cmds[1], "--unit=") || h.stdin[1] != g.Script() {
		t.Errorf("ran %q with %q", h.cmds, h.stdin)
	}
	if !strings.Contains(h.cmds[1], "cp -a -- ") || !strings.Contains(h.cmds[1], ".absent") {
		t.Errorf("the files aren't copied:\n%s", h.cmds[1])
	}

	// No systemd: nothing changes unguarded.
	h = &host{res: []ssh.Result{fail(1, "")}}
	if err := Arm(ctx, h, g); err == nil || !strings.Contains(err.Error(), "this host has no systemd-run") || len(h.cmds) != 1 {
		t.Errorf("no systemd: %v after %d runs", err, len(h.cmds))
	}
	h = &host{res: []ssh.Result{{}, fail(125, "refusing /tmp/x: anyone can create files in its directory\n")}}
	if err := Arm(ctx, h, g); err == nil || err.Error() != "confirm_after puts a file back as root, so it only guards one that nobody but root can lead somewhere else: refusing /tmp/x: anyone can create files in its directory" {
		t.Errorf("unsafe route: %v", err)
	}
	h = &host{res: []ssh.Result{{}, fail(1, "disk full")}}
	if err := Arm(ctx, h, g); err == nil || err.Error() != "scheduling the revert: exit status 1: disk full" {
		t.Errorf("failed: %v", err)
	}
	lost := errors.New("connection lost")
	if err := Arm(ctx, &host{err: lost}, g); err == nil || !strings.Contains(err.Error(), "no systemd-run") {
		t.Errorf("lost on the check: %v", err)
	}
	h = &host{res: []ssh.Result{{}}}
	h2 := &lateFail{host: h, err: lost}
	if err := Arm(ctx, h2, g); !errors.Is(err, lost) || !strings.HasPrefix(err.Error(), "scheduling the revert: ") {
		t.Errorf("lost on the schedule: %v", err)
	}
	if err := Arm(ctx, nil, Guard{ID: "x"}); err == nil {
		t.Error("a guard with no time passed")
	}
}

// lateFail answers the first run from host, then fails.
type lateFail struct {
	*host
	err error
}

func (l *lateFail) Run(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	if len(l.host.res) == 0 {
		return ssh.Result{}, l.err
	}
	return l.host.Run(ctx, cmd, stdin)
}

func TestRevertNow(t *testing.T) {
	ctx := context.Background()
	h := &host{res: []ssh.Result{{}}}
	if err := RevertNow(ctx, h, g); err != nil || !strings.Contains(h.cmds[0], "systemctl stop 'conn3x-revert-abc'.timer") || !strings.Contains(h.cmds[0], "/bin/sh '/var/lib/conn3x/revert/abc'/revert.sh") {
		t.Errorf("%v, ran %q", err, h.cmds)
	}
	// With nothing on stderr, stdout says what went wrong.
	h = &host{res: []ssh.Result{{ExitCode: 2, Stdout: []byte("cp: cannot stat\n")}}}
	if err := RevertNow(ctx, h, g); err == nil || err.Error() != "reverting: exit status 2: cp: cannot stat" {
		t.Errorf("got %v", err)
	}
	if err := RevertNow(ctx, &host{err: errors.New("down")}, g); err == nil || err.Error() != "reverting: down" {
		t.Errorf("got %v", err)
	}
}

func TestConfirm(t *testing.T) {
	ctx := context.Background()
	h := &host{res: []ssh.Result{{}}}
	if err := Confirm(ctx, h, g); err != nil || !strings.Contains(h.cmds[0], "systemctl is-active --quiet 'conn3x-revert-abc'.timer || exit 3") {
		t.Errorf("%v, ran %q", err, h.cmds)
	}
	if err := Confirm(ctx, &host{res: []ssh.Result{fail(3, "")}}, g); !errors.Is(err, ErrAlreadyReverted) {
		t.Errorf("fired: %v", err)
	}
	if err := Confirm(ctx, &host{res: []ssh.Result{fail(1, "Failed to stop\n")}}, g); err == nil || err.Error() != "cancelling the revert: exit status 1: Failed to stop" {
		t.Errorf("failed: %v", err)
	}
	if err := Confirm(ctx, &host{err: errors.New("down")}, g); err == nil || err.Error() != "down" {
		t.Errorf("lost: %v", err)
	}
}

func TestScriptWithoutReload(t *testing.T) {
	if s := (Guard{ID: "x"}).Script(); strings.Contains(s, "|| true") {
		t.Errorf("a guard with no undo or reload runs one:\n%s", s)
	}
}
