// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	conn3xagent "github.com/opentofu/opentofu/internal/conn3x/agent"
	"github.com/opentofu/opentofu/internal/conn3x/agent/agentpb"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/modules/moduletest"
)

// agent is a Serve running in this process, with the pipes to talk to it.
type agent struct {
	stdin  *io.PipeWriter
	stdout *io.PipeReader
	done   chan error
}

// serve starts Serve and reads its Hello.
func serve(t *testing.T) agent {
	t.Helper()
	in, stdin := io.Pipe()
	stdout, out := io.Pipe()
	a := agent{stdin: stdin, stdout: stdout, done: make(chan error, 1)}
	go func() { a.done <- Serve(context.Background(), in, out); out.Close() }()
	t.Cleanup(func() { stdin.Close(); stdout.Close() })

	hello, err := agentpb.ReadFrame(stdout)
	if err != nil || hello.Hello == nil || hello.Hello.Version != agentpb.ProtocolVersion {
		t.Fatalf("first frame %+v, %v; want Hello", hello, err)
	}
	return a
}

func (a agent) send(t *testing.T, e *agentpb.Envelope) {
	t.Helper()
	if err := agentpb.WriteFrame(a.stdin, e); err != nil {
		t.Fatal(err)
	}
}

// reply reads the next frame, failing if none comes within a few seconds.
func (a agent) reply(t *testing.T) *agentpb.Envelope {
	t.Helper()
	got := make(chan *agentpb.Envelope, 1)
	go func() {
		e, _ := agentpb.ReadFrame(a.stdout)
		got <- e
	}()
	select {
	case e := <-got:
		if e == nil {
			t.Fatal("the agent's output ended")
		}
		return e
	case <-time.After(waitDelay + 5*time.Second):
		t.Fatal("no reply from the agent")
		return nil
	}
}

// exited waits for Serve to return.
func (a agent) exited(t *testing.T) error {
	t.Helper()
	select {
	case err := <-a.done:
		return err
	case <-time.After(waitDelay + 5*time.Second):
		t.Fatal("Serve kept running")
		return nil
	}
}

// startSleeper runs cmd, which writes the pid of something it leaves
// running to PIDFILE, and returns that pid.
func (a agent) startSleeper(t *testing.T, id uint64, cmd string) int {
	t.Helper()
	pidFile := filepath.Join(t.TempDir(), "pid")
	cmd = strings.ReplaceAll(cmd, "PIDFILE", pidFile)
	a.send(t, &agentpb.Envelope{ID: id, Exec: &agentpb.ExecRequest{Cmd: cmd}})
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		b, _ := os.ReadFile(pidFile)
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
			return pid
		}
	}
	t.Fatal("the command never started")
	return 0
}

// gone fails unless pid exits within a few seconds. An orphan is reaped by
// init, which can take a moment.
func gone(t *testing.T, pid int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); syscall.Kill(pid, 0) == nil; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("process %d outlived its request", pid)
		}
	}
}

func TestServeExitsOnStdinEOF(t *testing.T) {
	a := serve(t)
	go func() { _, _ = io.Copy(io.Discard, a.stdout) }()
	pid := a.startSleeper(t, 1, "sleep 60 & echo $! > PIDFILE; wait")
	a.stdin.Close()
	if err := a.exited(t); err != nil {
		t.Fatalf("Serve: %v, want nil on EOF", err)
	}
	gone(t, pid)
}

func TestServeStopsWhenOutputBreaks(t *testing.T) {
	a := serve(t)
	pid := a.startSleeper(t, 1, "sleep 60 & echo $! > PIDFILE; wait")
	// Nobody reads the agent any more. The next reply fails to write,
	// and that has to take down the command still running.
	a.stdout.Close()
	a.send(t, &agentpb.Envelope{ID: 2, Exec: &agentpb.ExecRequest{Cmd: "true"}})
	if err := a.exited(t); err == nil {
		t.Fatal("Serve returned nil after its output broke")
	}
	gone(t, pid)
}

func TestCancelDoesNotWaitForEscapedChild(t *testing.T) {
	if _, err := os.Stat("/usr/bin/perl"); err != nil {
		t.Skip("needs perl to leave the process group")
	}
	a := serve(t)
	// perl leaves the process group but keeps stdout open, so killing
	// the group doesn't close the pipe.
	pid := a.startSleeper(t, 1, `perl -e 'setpgrp(0,0); open(F, ">", $ARGV[0]); print F $$; close F; sleep 60' PIDFILE & wait`)
	a.send(t, &agentpb.Envelope{ID: 1, Cancel: &agentpb.Cancel{}})
	if e := a.reply(t); e.Error == nil || e.Error.Code != agentpb.CodeCanceled {
		t.Fatalf("reply %+v, want CANCELED", e)
	}
	a.stdin.Close()
	if err := a.exited(t); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
}

func TestOutputOverLimitKillsCommand(t *testing.T) {
	defer func(old int) { MaxOutput = old }(MaxOutput)
	MaxOutput = 1 << 20
	a := serve(t)
	a.send(t, &agentpb.Envelope{ID: 1, Exec: &agentpb.ExecRequest{Cmd: "yes"}})
	e := a.reply(t)
	if e.Error == nil || e.Error.Code != agentpb.CodeInternal || !strings.Contains(e.Error.Message, "output exceeds 1 MiB") {
		t.Fatalf("reply %+v, want INTERNAL output exceeds 1 MiB", e)
	}

	// Output right at the limit still comes back whole.
	a.send(t, &agentpb.Envelope{ID: 2, Exec: &agentpb.ExecRequest{Cmd: "head -c 1048575 /dev/zero; printf x >&2"}})
	if e := a.reply(t); e.Result == nil || len(e.Result.Stdout)+len(e.Result.Stderr) != MaxOutput {
		t.Fatalf("reply %+v, want %d bytes of output", e, MaxOutput)
	}
}

func TestKilledBySignalExits128PlusN(t *testing.T) {
	a := serve(t)
	a.send(t, &agentpb.Envelope{ID: 1, Exec: &agentpb.ExecRequest{Cmd: "kill -9 $$"}})
	if e := a.reply(t); e.Result == nil || e.Result.ExitCode != 137 {
		t.Fatalf("reply %+v, want exit 137", e)
	}
}

func TestFileReadUnknownOwnerFallsBack(t *testing.T) {
	names = func(uid, gid uint32) (string, string, error) { return "", "", errors.New("user: unknown userid 4242") }
	t.Cleanup(func() { names = lookupNames })
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := client(t)
	if _, err := c.ReadFile(context.Background(), p); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("ReadFile = %v, want unsupported", err)
	}
	got, err := file.Read(context.Background(), c, p)
	if err != nil {
		t.Fatal(err)
	}
	want, err := file.Read(context.Background(), moduletest.Local{}, p)
	if err != nil || got != want {
		t.Fatalf("got %+v, the shell gives %+v, %v", got, want, err)
	}
}

func TestReadUnitWithoutDBusIsUnsupported(t *testing.T) {
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path="+filepath.Join(t.TempDir(), "none"))
	c := client(t)
	if _, err := c.ReadUnit(context.Background(), "sshd.service"); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("ReadUnit = %v, want unsupported", err)
	}
}

// client connects to a Serve in this process.
func client(t *testing.T) *conn3xagent.Client {
	t.Helper()
	in, toAgent := io.Pipe()
	fromAgent, out := io.Pipe()
	go func() { _ = Serve(context.Background(), in, out); out.Close() }()
	c, err := conn3xagent.NewClient(context.Background(), pipeConn{fromAgent, toAgent})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

type pipeConn struct {
	*io.PipeReader
	*io.PipeWriter
}

func (p pipeConn) Close() error {
	p.PipeWriter.Close()
	return p.PipeReader.Close()
}
