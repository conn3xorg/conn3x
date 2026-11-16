// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package schedule

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// crontabHost answers every crontab command with res, and records them
// with their stdin.
type crontabHost struct {
	res   ssh.Result
	err   error
	cmds  []string
	stdin []string
}

func (h *crontabHost) Run(_ context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	h.cmds, h.stdin = append(h.cmds, cmd), append(h.stdin, string(stdin))
	return h.res, h.err
}

func failed(code int, stderr string) ssh.Result {
	return ssh.Result{ExitCode: code, Stderr: []byte(stderr)}
}

func TestReadCrontab(t *testing.T) {
	ctx := context.Background()
	h := &crontabHost{res: ssh.Result{Stdout: []byte("0 * * * * true\n")}}
	if got, err := ReadCrontab(ctx, h, "it's"); err != nil || got != "0 * * * * true\n" || !strings.HasSuffix(h.cmds[0], `exec crontab -u 'it'\''s' -l`) {
		t.Errorf("got %q, %v, ran %q", got, err, h.cmds)
	}
	if got, err := ReadCrontab(ctx, &crontabHost{res: failed(1, "no crontab for app\n")}, "app"); err != nil || got != "" {
		t.Errorf("none: %q, %v", got, err)
	}
	big := &crontabHost{res: ssh.Result{Stdout: make([]byte, MaxCrontab+1)}}
	if _, err := ReadCrontab(ctx, big, "app"); err == nil || !strings.Contains(err.Error(), "the most Conn3x reads of it") {
		t.Errorf("too big: %v", err)
	}
	lost := errors.New("connection lost")
	if _, err := ReadCrontab(ctx, &crontabHost{err: lost}, "app"); !errors.Is(err, lost) {
		t.Errorf("lost: %v", err)
	}
	// Each failure the crontab command reports says what to do about it.
	for stderr, want := range map[string]string{
		"must be privileged to use -u\n":          "needs root; set become = true",
		"crontab: user `ghost' unknown\n":         "user app does not exist",
		"/var/spool/cron: Permission denied\n":    "needs root",
		"crontab: something else went wrong\n":    "crontab for app: crontab: something else went wrong",
		"You (app) are not allowed to use this\n": "needs root",
	} {
		if _, err := ReadCrontab(ctx, &crontabHost{res: failed(1, stderr)}, "app"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", stderr, err, want)
		}
	}
	if _, err := ReadCrontab(ctx, &crontabHost{res: failed(noCrontab, "")}, "app"); !errors.Is(err, ErrNoCrontab) {
		t.Errorf("no crontab command: %v", err)
	}
}

func TestWriteAndRemoveCrontab(t *testing.T) {
	ctx := context.Background()
	h := &crontabHost{}
	if err := WriteCrontab(ctx, h, "app", "0 * * * * true\n"); err != nil || !strings.HasSuffix(h.cmds[0], "-u 'app' -") || h.stdin[0] != "0 * * * * true\n" {
		t.Errorf("write: %v, ran %q with %q", err, h.cmds, h.stdin)
	}
	// Writing nothing removes the crontab.
	h = &crontabHost{}
	if err := WriteCrontab(ctx, h, "app", ""); err != nil || !strings.HasSuffix(h.cmds[0], "-u 'app' -r") {
		t.Errorf("empty write: %v, ran %q", err, h.cmds)
	}
	if err := WriteCrontab(ctx, &crontabHost{res: failed(noCrontab, "")}, "app", "x\n"); !errors.Is(err, ErrNoCrontab) {
		t.Errorf("write without crontab: %v", err)
	}
	lost := errors.New("connection lost")
	if err := WriteCrontab(ctx, &crontabHost{err: lost}, "app", "x\n"); !errors.Is(err, lost) {
		t.Errorf("write lost: %v", err)
	}
	if err := RemoveCrontab(ctx, &crontabHost{res: failed(1, "no crontab for app\n")}, "app"); err != nil {
		t.Errorf("removing none: %v", err)
	}
	if err := RemoveCrontab(ctx, &crontabHost{res: failed(1, "must be privileged\n")}, "app"); err == nil || !strings.Contains(err.Error(), "needs root") {
		t.Errorf("remove refused: %v", err)
	}
	if err := RemoveCrontab(ctx, &crontabHost{err: lost}, "app"); !errors.Is(err, lost) {
		t.Errorf("remove lost: %v", err)
	}
}
