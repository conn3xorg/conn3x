// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package pkg

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// updates fails apt-get update with stderr for its first fails runs.
type updates struct {
	fails  int
	stderr string
	runs   int
}

func (u *updates) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	if !strings.Contains(cmd, "apt-get") || !strings.Contains(cmd, " update") {
		return ssh.Result{}, nil
	}
	u.runs++
	if u.runs <= u.fails {
		return ssh.Result{ExitCode: 100, Stderr: []byte(u.stderr)}, nil
	}
	return ssh.Result{}, nil
}

// A fetch that fails, as a mirror's 403 or 520 does, is tried again up to
// Ansible's five times; anything else fails at once.
func TestUpdateListsRetries(t *testing.T) {
	defer func(w, j time.Duration) { updateMaxWait, updateJitter = w, j }(updateMaxWait, updateJitter)
	updateMaxWait, updateJitter = 0, 0
	const fetch = "E: Failed to fetch http://archive.ubuntu.com/ubuntu/dists/noble/InRelease  520  <none>\n"

	u := &updates{fails: 2, stderr: fetch}
	if err := UpdateLists(ctx, u); err != nil || u.runs != 3 {
		t.Errorf("two failed fetches, then a good one: %v after %d runs", err, u.runs)
	}
	u = &updates{fails: 99, stderr: fetch}
	if err := UpdateLists(ctx, u); err == nil || u.runs != updateTries || !strings.Contains(err.Error(), "failed 5 times") || !strings.Contains(err.Error(), "520") {
		t.Errorf("a fetch that never works: %v after %d runs", err, u.runs)
	}
	u = &updates{fails: 99, stderr: "E: Malformed entry 3 in list file /etc/apt/sources.list.d/x.list\n"}
	if err := UpdateLists(ctx, u); err == nil || u.runs != 1 {
		t.Errorf("a broken sources file is tried again: %v after %d runs", err, u.runs)
	}
}

// The waits are Ansible's: 1, 2, 4 and 8 seconds, never past the cap.
func TestUpdateListsWaits(t *testing.T) {
	defer func(w, j time.Duration) { updateMaxWait, updateJitter = w, j }(updateMaxWait, updateJitter)
	updateMaxWait, updateJitter = 3*time.Millisecond, 0
	start := time.Now()
	u := &updates{fails: 99, stderr: "E: Failed to fetch x  403  Forbidden\n"}
	_ = UpdateLists(ctx, u)
	// Every wait is capped at 3ms, so four of them take well under a second.
	if d := time.Since(start); d > time.Second {
		t.Errorf("waits ignored the cap: %v", d)
	}
}
