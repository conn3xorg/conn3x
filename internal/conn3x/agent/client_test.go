// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/agent/agentpb"
	"github.com/opentofu/opentofu/internal/conn3x/agent/server"
	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/moduletest"
)

var ctx = context.Background()

// pipeConn joins the two ends of a pair of pipes into one connection.
type pipeConn struct {
	*io.PipeReader
	*io.PipeWriter
}

func (p pipeConn) Close() error {
	p.PipeWriter.Close()
	return p.PipeReader.Close()
}

// pipes returns the client's end and the agent's end of a connection.
func pipes() (client, agent pipeConn) {
	agentIn, clientOut := io.Pipe()
	clientIn, agentOut := io.Pipe()
	return pipeConn{clientIn, clientOut}, pipeConn{agentIn, agentOut}
}

// startAgent serves an agent in this process and connects to it.
func startAgent(t *testing.T) *Client {
	t.Helper()
	conn, end := pipes()
	go func() {
		_ = server.Serve(ctx, end, end)
		end.Close()
	}()
	c, err := NewClient(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestExecMatchesShell(t *testing.T) {
	moduletest.RunnerConformance(t, func(t *testing.T) modules.Runner { return startAgent(t) })

	// The agent runs commands where it was started, as the shell would.
	c := startAgent(t)
	got, err := c.Run(ctx, "pwd", nil)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := moduletest.Local{}.Run(ctx, "pwd", nil)
	if string(got.Stdout) != string(want.Stdout) {
		t.Fatalf("pwd = %q, want %q", got.Stdout, want.Stdout)
	}
}

func TestFileReadAgentMatchesShell(t *testing.T) {
	t.Run("shell", func(t *testing.T) { moduletest.FileConformance(t, moduletest.Local{}, moduletest.Local{}) })
	t.Run("agent", func(t *testing.T) { moduletest.FileConformance(t, moduletest.Local{}, startAgent(t)) })
}

func TestReadsCancel(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("godbus reads DBUS_SYSTEM_BUS_ADDRESS only on Linux")
	}
	// A system bus that accepts and then says nothing.
	dir, err := os.MkdirTemp("", "bus")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	l, err := net.Listen("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path="+filepath.Join(dir, "s"))

	conn, end := pipes()
	served := make(chan struct{})
	go func() {
		_ = server.Serve(ctx, end, end)
		end.Close()
		close(served)
	}()
	c, err := NewClient(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.ReadUnit(cctx, "sshd.service"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReadUnit = %v, want the deadline", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("canceling took %s", d)
	}
	// The agent is still there for the next request.
	if _, err := c.ReadFile(ctx, "/"); err != nil {
		t.Fatal(err)
	}
	// And the canceled read let go: the agent waits for its reads before
	// it exits.
	c.Close()
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("the agent is still waiting for the canceled read")
	}
}

func TestExecConcurrent(t *testing.T) {
	c := startAgent(t)
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := c.Run(ctx, fmt.Sprintf("sleep 0.0%d; printf %d; printf e%d >&2; exit %d", i%10, i, i, i), nil)
			if err != nil {
				t.Errorf("run %d: %v", i, err)
				return
			}
			if string(res.Stdout) != strconv.Itoa(i) || string(res.Stderr) != fmt.Sprintf("e%d", i) || res.ExitCode != i {
				t.Errorf("run %d got stdout %q stderr %q exit %d", i, res.Stdout, res.Stderr, res.ExitCode)
			}
		}()
	}
	wg.Wait()
}

func TestCancelKillsProcessGroup(t *testing.T) {
	c := startAgent(t)
	pidFile := filepath.Join(t.TempDir(), "pid")
	runCtx, cancel := context.WithCancel(ctx)
	errc := make(chan error, 1)
	go func() {
		// The sleep is a grandchild: only killing the group reaches it.
		_, err := c.Run(runCtx, "sleep 60 & echo $! > "+pidFile+"; wait", nil)
		errc <- err
	}()
	pid := waitForPID(t, pidFile)
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run ignored cancellation")
	}
	waitGone(t, pid)

	// The agent is still there for the next command.
	if res, err := c.Run(ctx, "echo ok", nil); err != nil || string(res.Stdout) != "ok\n" {
		t.Fatalf("after cancel: %q, %v", res.Stdout, err)
	}
}

func TestHandshakeRejectsOtherProtocol(t *testing.T) {
	for _, first := range []*agentpb.Envelope{
		{Hello: &agentpb.Hello{Version: agentpb.ProtocolVersion + 1}},
		{ID: 1, Result: &agentpb.ExecResponse{}},
	} {
		conn, end := pipes()
		go func() { _ = agentpb.WriteFrame(end, first) }()
		_, err := NewClient(ctx, conn)
		if !errors.Is(err, ErrProtocol) {
			t.Errorf("first frame %+v: err = %v, want ErrProtocol", first, err)
		}
		end.Close()
	}
}

func TestRunAfterAgentDied(t *testing.T) {
	conn, end := pipes()
	go func() {
		// An agent that says hello, takes one request and dies.
		_ = agentpb.WriteFrame(end, &agentpb.Envelope{Hello: &agentpb.Hello{Version: agentpb.ProtocolVersion}})
		_, _ = agentpb.ReadFrame(end)
		end.Close()
	}()
	c, err := NewClient(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Run(ctx, "true", nil); !errors.Is(err, ErrAgentGone) {
		t.Fatalf("in flight: err = %v, want ErrAgentGone", err)
	}
	if _, err := c.Run(ctx, "true", nil); !errors.Is(err, ErrAgentGone) {
		t.Fatalf("afterwards: err = %v, want ErrAgentGone", err)
	}
	<-c.Done()
	if c.Err() == nil {
		t.Fatal("Err() is nil after the agent died")
	}
}

// waitForPID reads a pid a command writes to path.
func waitForPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, _ := os.ReadFile(path)
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			return pid
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no pid in %s", path)
	return 0
}

// waitGone fails unless pid exits within a few seconds.
func waitGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatalf("process %d outlived its request", pid)
}

func TestRunAfterUnreadableFrame(t *testing.T) {
	conn, end := pipes()
	sent := make(chan *agentpb.Envelope, 1)
	go func() {
		_ = agentpb.WriteFrame(end, &agentpb.Envelope{Hello: &agentpb.Hello{Version: agentpb.ProtocolVersion}})
		// A frame longer than MaxFrame: the client must stop and hang up.
		_, _ = end.Write([]byte{0xff, 0xff, 0xff, 0xff})
		e, _ := agentpb.ReadFrame(end)
		sent <- e
		end.Close()
	}()
	c, err := NewClient(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the client kept reading after a bad frame")
	}
	if !errors.Is(c.Err(), agentpb.ErrFrameTooLarge) {
		t.Fatalf("Err() = %v, want ErrFrameTooLarge", c.Err())
	}
	if _, err := c.Run(ctx, "true", nil); !errors.Is(err, ErrAgentGone) {
		t.Fatalf("err = %v, want ErrAgentGone", err)
	}
	if e := <-sent; e != nil {
		t.Fatalf("the client sent %+v to an agent it had stopped reading", e)
	}
}

func TestHelloTimeout(t *testing.T) {
	defer func(old time.Duration) { helloTimeout = old }(helloTimeout)
	helloTimeout = 50 * time.Millisecond
	conn, end := pipes()
	defer end.Close()
	start := time.Now()
	if _, err := NewClient(ctx, conn); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want a deadline", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("NewClient took %s", took)
	}
}

func TestAgentShutdownIsAgentGone(t *testing.T) {
	conn, end := pipes()
	serveCtx, shutdown := context.WithCancel(ctx)
	go func() {
		_ = server.Serve(serveCtx, end, end)
		end.Close()
	}()
	c, err := NewClient(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	pidFile := filepath.Join(t.TempDir(), "pid")
	errc := make(chan error, 1)
	go func() {
		_, err := c.Run(ctx, "sleep 60 & echo $! > "+pidFile+"; wait", nil)
		errc <- err
	}()
	pid := waitForPID(t, pidFile)
	shutdown()
	if err := <-errc; !errors.Is(err, ErrAgentGone) {
		t.Fatalf("err = %v, want ErrAgentGone", err)
	}
	waitGone(t, pid)
}
