// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package transport is what Conn3x needs from a connection to a host.
// Modules only run commands, files included (they travel on stdin), so Conn
// is all most of them use. The rest is optional: a feature that needs
// Starter, Dialer or Shell checks for it and says plainly when the
// connection a host was reached over doesn't have it.
package transport

import (
	"context"
	"io"
	"net"
)

// Result is the outcome of one command.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Conn is an open connection to one host. It is safe for concurrent use.
type Conn interface {
	// Run runs cmd under a POSIX shell, writing stdin to it.
	Run(ctx context.Context, cmd string, stdin []byte) (Result, error)
	// Alive reports whether the connection still answers.
	Alive() bool
	// Addr names the host for messages, such as "web1:22".
	Addr() string
	Close() error
}

// Process is a command left running by Starter. Reading reads its stdout
// and writing writes its stdin.
type Process interface {
	io.ReadWriteCloser
	// Stderr is a snapshot of what the command has written to stderr so far.
	Stderr() []byte
	// Wait waits for the command to exit. A non-zero exit is an error.
	Wait() error
}

// Starter starts a long-running command with streamed I/O, as the agent
// needs.
type Starter interface {
	Start(ctx context.Context, cmd string) (Process, error)
}

// Dialer opens a TCP connection from the host, for ssh_tunnel and
// wait_for's url.
type Dialer interface {
	DialRemote(ctx context.Context, addr string) (net.Conn, error)
}

// Shell talks to devices with no POSIX shell, such as network CLIs.
type Shell interface {
	// RunRaw runs cmd as given, with no shell or locale around it.
	RunRaw(ctx context.Context, cmd string, stdin []byte) (Result, error)
	// RunShell writes stdin to the login shell and reads until it exits.
	RunShell(ctx context.Context, stdin []byte) (Result, error)
}
