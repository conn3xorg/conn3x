// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/agent/agentpb"
)

func TestServeExitsOnStdinEOF(t *testing.T) {
	in, stdin := io.Pipe()
	stdout, out := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), in, out); out.Close() }()

	hello, err := agentpb.ReadFrame(stdout)
	if err != nil || hello.Hello == nil || hello.Hello.Version != agentpb.ProtocolVersion {
		t.Fatalf("first frame %+v, %v; want Hello", hello, err)
	}
	go func() { _, _ = io.Copy(io.Discard, stdout) }()

	pidFile := filepath.Join(t.TempDir(), "pid")
	exec := &agentpb.ExecRequest{Cmd: "sleep 60 & echo $! > " + pidFile + "; wait"}
	if err := agentpb.WriteFrame(stdin, &agentpb.Envelope{ID: 1, Exec: exec}); err != nil {
		t.Fatal(err)
	}
	var pid int
	for deadline := time.Now().Add(5 * time.Second); pid == 0 && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		b, _ := os.ReadFile(pidFile)
		pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	if pid == 0 {
		t.Fatal("the command never started")
	}

	stdin.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v, want nil on EOF", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve kept running after stdin closed")
	}
	// The orphaned sleep is reaped by init, which can take a moment.
	for deadline := time.Now().Add(5 * time.Second); syscall.Kill(pid, 0) == nil; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("process %d outlived the agent", pid)
		}
	}
}
