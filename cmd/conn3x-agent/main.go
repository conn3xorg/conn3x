// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Command conn3x-agent is the host agent conn3x starts over SSH. It reads
// requests on stdin and answers on stdout until stdin closes.
//
// It may import only the standard library, protowire, go-systemd's D-Bus
// client and the agent's own packages; TestAgentDependencies in
// internal/conn3x/agent enforces that.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/opentofu/opentofu/internal/conn3x/agent/server"
)

func main() {
	// A broken stdout must be an error Serve sees, so it can kill what is
	// still running, not a signal that kills the agent and orphans it.
	signal.Ignore(syscall.SIGPIPE)
	// A signal kills the commands still running before the agent exits.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	if err := server.Serve(ctx, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "conn3x-agent:", err)
		os.Exit(1)
	}
}
