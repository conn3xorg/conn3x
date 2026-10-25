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
	"os/exec"
	"sync"
	"syscall"

	"github.com/opentofu/opentofu/internal/conn3x/agent/agentpb"
)

// Serve says Hello on out, then runs the requests read from in until in
// ends. When it ends, or ctx is done, every running command is killed and
// waited for. A clean end of in returns nil.
func Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	s := &server{out: out, running: map[uint64]context.CancelFunc{}}
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
	wmu sync.Mutex
	out io.Writer

	mu      sync.Mutex
	running map[uint64]context.CancelFunc
}

// send writes one frame; responses from concurrent requests never interleave.
func (s *server) send(e *agentpb.Envelope) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return agentpb.WriteFrame(s.out, e)
}

func (s *server) fail(id uint64, code agentpb.Code, msg string) {
	_ = s.send(&agentpb.Envelope{ID: id, Error: &agentpb.Error{Code: code, Message: msg}})
}

// exec runs a command the way the shell transport does, in its own process
// group so that canceling it kills everything it started.
func (s *server) exec(ctx context.Context, id uint64, req *agentpb.ExecRequest) {
	c := exec.CommandContext(ctx, "/bin/sh", "-c", "export LC_ALL=C; "+req.Cmd)
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Cancel = func() error { return syscall.Kill(-c.Process.Pid, syscall.SIGKILL) }
	c.Stdin = bytes.NewReader(req.Stdin)
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr

	err := c.Run()
	var exit *exec.ExitError
	switch {
	case ctx.Err() != nil:
		s.fail(id, agentpb.CodeCanceled, "canceled")
		return
	case err != nil && !errors.As(err, &exit):
		s.fail(id, agentpb.CodeInternal, err.Error())
		return
	}
	res := &agentpb.ExecResponse{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: int32(c.ProcessState.ExitCode())}
	if err := s.send(&agentpb.Envelope{ID: id, Result: res}); errors.Is(err, agentpb.ErrFrameTooLarge) {
		s.fail(id, agentpb.CodeInternal, fmt.Sprintf("the command's output is too large for the agent: %v", err))
	}
}
