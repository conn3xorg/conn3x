// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package agent is conn3x's side of the host agent: a small static binary
// that runs module commands over one long-lived SSH session, so a command
// costs one round trip instead of a new session each time.
package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/agent/agentpb"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// helloTimeout bounds the wait for the agent's Hello, which under sudo
// includes PAM.
var helloTimeout = 20 * time.Second

var (
	// ErrAgentGone is wrapped when the agent stops while conn3x still
	// needs it. Requests in flight fail with it and are never retried.
	ErrAgentGone = errors.New("the conn3x agent stopped")
	// ErrProtocol is wrapped when the agent says something unexpected,
	// such as a Hello for another protocol version.
	ErrProtocol = errors.New("the conn3x agent speaks another protocol")
)

// Client sends commands to a running agent. It satisfies modules.Runner
// and is safe for concurrent use; requests run in parallel on the agent.
type Client struct {
	rw  io.ReadWriteCloser
	wmu sync.Mutex

	mu      sync.Mutex
	nextID  uint64
	pending map[uint64]chan *agentpb.Envelope

	done chan struct{} // closed when the agent's output ends
	err  error         // why it ended; set before done is closed
}

// NewClient waits for the agent's Hello on rw and checks its protocol
// version. On failure rw is closed.
func NewClient(ctx context.Context, rw io.ReadWriteCloser) (*Client, error) {
	ctx, cancel := context.WithTimeout(ctx, helloTimeout)
	defer cancel()
	type frame struct {
		e   *agentpb.Envelope
		err error
	}
	first := make(chan frame, 1)
	go func() {
		e, err := agentpb.ReadFrame(rw)
		first <- frame{e, err}
	}()

	var f frame
	select {
	case f = <-first:
	case <-ctx.Done():
		rw.Close()
		return nil, fmt.Errorf("waiting for the conn3x agent to start: %w", ctx.Err())
	}
	switch {
	case f.err != nil:
		rw.Close()
		return nil, fmt.Errorf("%w before it started: %v", ErrAgentGone, f.err)
	case f.e.Hello == nil:
		rw.Close()
		return nil, fmt.Errorf("%w: its first message was not a hello", ErrProtocol)
	case f.e.Hello.Version != agentpb.ProtocolVersion:
		rw.Close()
		return nil, fmt.Errorf("%w: version %d, conn3x needs %d", ErrProtocol, f.e.Hello.Version, agentpb.ProtocolVersion)
	}

	c := &Client{rw: rw, pending: map[uint64]chan *agentpb.Envelope{}, done: make(chan struct{})}
	go c.read()
	return c, nil
}

// read hands each response to the request waiting for it.
func (c *Client) read() {
	for {
		e, err := agentpb.ReadFrame(c.rw)
		if err != nil {
			// Hang up, so nothing more is sent to an agent nobody hears.
			c.err = err
			close(c.done)
			c.rw.Close()
			return
		}
		c.mu.Lock()
		ch := c.pending[e.ID]
		delete(c.pending, e.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- e
		}
	}
}

// Run executes cmd on the host with /bin/sh in the C locale, exactly as the
// shell transport does. A non-zero exit status is reported in Result.
// Canceling ctx kills the command and everything it started.
func (c *Client) Run(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	if err := ctx.Err(); err != nil {
		return ssh.Result{}, err
	}
	select {
	case <-c.done:
		return ssh.Result{}, c.gone()
	default:
	}
	ch := make(chan *agentpb.Envelope, 1)
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	c.pending[id] = ch
	c.mu.Unlock()

	err := c.send(&agentpb.Envelope{ID: id, Exec: &agentpb.ExecRequest{Cmd: cmd, Stdin: stdin}})
	if err != nil {
		c.forget(id)
		if errors.Is(err, agentpb.ErrFrameTooLarge) {
			return ssh.Result{}, fmt.Errorf("conn3x agent: %w", err)
		}
		return ssh.Result{}, c.gone()
	}

	var e *agentpb.Envelope
	select {
	case e = <-ch:
	case <-ctx.Done():
		c.forget(id)
		_ = c.send(&agentpb.Envelope{ID: id, Cancel: &agentpb.Cancel{}})
		return ssh.Result{}, ctx.Err()
	case <-c.done:
		select {
		case e = <-ch:
		default:
			return ssh.Result{}, c.gone()
		}
	}

	switch {
	case e.Result != nil:
		return ssh.Result{Stdout: e.Result.Stdout, Stderr: e.Result.Stderr, ExitCode: int(e.Result.ExitCode)}, nil
	case e.Error != nil && e.Error.Code == agentpb.CodeCanceled:
		// Only the agent cancels a request whose ctx is still live: it is
		// shutting down.
		return ssh.Result{}, fmt.Errorf("%w: it was stopped while running the command", ErrAgentGone)
	case e.Error != nil && e.Error.Code == agentpb.CodeUnsupported:
		return ssh.Result{}, fmt.Errorf("conn3x agent: %s: %w", e.Error.Message, errors.ErrUnsupported)
	case e.Error != nil:
		return ssh.Result{}, fmt.Errorf("conn3x agent: %s: %s", e.Error.Code, e.Error.Message)
	}
	return ssh.Result{}, fmt.Errorf("%w: an empty reply to request %d", ErrProtocol, id)
}

// Done is closed when the agent's output ends; after that every Run fails
// with ErrAgentGone.
func (c *Client) Done() <-chan struct{} { return c.done }

// Err says why the agent's output ended, or nil while it is running.
func (c *Client) Err() error {
	select {
	case <-c.done:
		return c.err
	default:
		return nil
	}
}

// Close stops the agent by ending its input.
func (c *Client) Close() error {
	return c.rw.Close()
}

func (c *Client) send(e *agentpb.Envelope) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return agentpb.WriteFrame(c.rw, e)
}

func (c *Client) forget(id uint64) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

// gone is the error for a request the agent can no longer answer.
func (c *Client) gone() error {
	select {
	case <-c.done:
		if errors.Is(c.err, io.EOF) {
			return ErrAgentGone
		}
		return fmt.Errorf("%w: %v", ErrAgentGone, c.err)
	default:
		return ErrAgentGone
	}
}
