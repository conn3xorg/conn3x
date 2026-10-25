// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package server is the host agent: it reads requests from conn3x and runs
// them on the host, each in its own goroutine.
//
// The agent binary links this package, so it may import only the standard
// library and agentpb.
package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/agent/agentpb"
)

// MaxOutput is the most stdout and stderr together that one command may
// write. A command that writes more is killed, so a runaway command can't
// exhaust the host's memory, and its reply always fits in a frame.
var MaxOutput = 255 << 20

// waitDelay bounds how long a finished or killed command's output pipes
// are waited for, in case something it started outside its process group
// still holds them.
const waitDelay = 2 * time.Second

// Serve says Hello on out, then runs the requests read from in until in
// ends. When it ends, when out can't be written, or when ctx is done,
// every running command is killed and waited for. A clean end of in
// returns nil.
func Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	s := &server{out: out, stop: cancel, running: map[uint64]context.CancelFunc{}}
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()

	if err := s.send(&agentpb.Envelope{Hello: &agentpb.Hello{Version: agentpb.ProtocolVersion}}); err != nil {
		return err
	}

	frames := make(chan *agentpb.Envelope)
	readErr := make(chan error, 1)
	go func() {
		for {
			e, err := agentpb.ReadFrame(in)
			if err != nil {
				readErr <- err
				return
			}
			select {
			case frames <- e:
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			if err := s.writeErr(); err != nil {
				return err
			}
			return ctx.Err()
		case err := <-readErr:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case e := <-frames:
			switch {
			case e.Exec != nil:
				reqCtx, stop := context.WithCancel(ctx)
				s.mu.Lock()
				s.running[e.ID] = stop
				s.mu.Unlock()
				wg.Add(1)
				go func() {
					defer wg.Done()
					s.exec(reqCtx, e.ID, e.Exec)
					s.mu.Lock()
					delete(s.running, e.ID)
					s.mu.Unlock()
					stop()
				}()
			case e.Cancel != nil:
				s.mu.Lock()
				stop := s.running[e.ID]
				s.mu.Unlock()
				if stop != nil {
					stop()
				}
			default:
				s.fail(e.ID, agentpb.CodeUnsupported, "this agent does not know that request")
			}
		}
	}
}

type server struct {
	wmu  sync.Mutex
	out  io.Writer
	werr error              // the first failed write
	stop context.CancelFunc // ends Serve

	mu      sync.Mutex
	running map[uint64]context.CancelFunc
}

// send writes one frame; responses from concurrent requests never
// interleave. Once a write fails nobody can hear the agent, so Serve stops
// and takes every running command with it.
func (s *server) send(e *agentpb.Envelope) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.werr != nil {
		return s.werr
	}
	if err := agentpb.WriteFrame(s.out, e); err != nil {
		s.werr = fmt.Errorf("writing to conn3x: %w", err)
		s.stop()
		return s.werr
	}
	return nil
}

func (s *server) writeErr() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return s.werr
}

func (s *server) fail(id uint64, code agentpb.Code, msg string) {
	_ = s.send(&agentpb.Envelope{ID: id, Error: &agentpb.Error{Code: code, Message: msg}})
}

// exec runs a command the way the shell transport does, in its own process
// group so that canceling it kills everything it started.
func (s *server) exec(ctx context.Context, id uint64, req *agentpb.ExecRequest) {
	runCtx, kill := context.WithCancel(ctx)
	defer kill()
	c := exec.CommandContext(runCtx, "/bin/sh", "-c", "export LC_ALL=C; "+req.Cmd)
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Cancel = func() error { return syscall.Kill(-c.Process.Pid, syscall.SIGKILL) }
	c.WaitDelay = waitDelay
	c.Stdin = bytes.NewReader(req.Stdin)
	budget := &budget{left: MaxOutput, over: kill}
	stdout, stderr := &capped{budget: budget}, &capped{budget: budget}
	c.Stdout, c.Stderr = stdout, stderr

	err := c.Run()
	var exit *exec.ExitError
	switch {
	case ctx.Err() != nil:
		s.fail(id, agentpb.CodeCanceled, "canceled")
		return
	case budget.exceeded():
		s.fail(id, agentpb.CodeInternal, fmt.Sprintf("the command's output exceeds %d MiB, the most the agent returns", MaxOutput>>20))
		return
	case err != nil && !errors.As(err, &exit) && !errors.Is(err, exec.ErrWaitDelay):
		s.fail(id, agentpb.CodeInternal, err.Error())
		return
	}
	res := &agentpb.ExecResponse{Stdout: stdout.buf.Bytes(), Stderr: stderr.buf.Bytes(), ExitCode: exitCode(c.ProcessState)}
	_ = s.send(&agentpb.Envelope{ID: id, Result: res})
}

// exitCode is the status the shell transport reports: 128 plus the signal
// for a shell killed by one, as sshd does.
func exitCode(ps *os.ProcessState) int32 {
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int32(ws.Signal())
	}
	return int32(ps.ExitCode())
}

// budget is the output a command has left, shared by its stdout and stderr.
type budget struct {
	mu   sync.Mutex
	left int
	over func() // kills the command
	hit  bool
}

func (b *budget) exceeded() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.hit
}

var errOutputLimit = errors.New("output limit reached")

// capped collects output until the budget runs out, then kills the command.
type capped struct {
	budget *budget
	buf    bytes.Buffer
}

func (w *capped) Write(p []byte) (int, error) {
	b := w.budget
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(p) > b.left {
		if !b.hit {
			b.hit = true
			b.over()
		}
		return 0, errOutputLimit
	}
	b.left -= len(p)
	return w.buf.Write(p)
}
