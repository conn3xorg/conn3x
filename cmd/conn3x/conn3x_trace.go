// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"os"
	"runtime/trace"
)

// envTrace names a file for a Go execution trace of the run, which shows
// where a plan waits as well as where it spends CPU: go tool trace <file>.
const envTrace = "CONN3X_TRACE"

// startTrace starts the trace envTrace asks for, and returns what stops it.
func startTrace() (stop func(), err error) {
	path := os.Getenv(envTrace)
	if path == "" {
		return func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("could not open %s output: %w", envTrace, err)
	}
	if err := trace.Start(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("could not start %s: %w", envTrace, err)
	}
	return func() { trace.Stop(); _ = f.Close() }, nil
}
