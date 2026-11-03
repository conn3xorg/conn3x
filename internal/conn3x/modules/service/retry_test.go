// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package service

import (
	"context"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// reexecing is a host whose systemctl fails the first n calls with stderr,
// the way it does while systemd re-executes itself.
type reexecing struct {
	host
	n      int
	stderr string
	only   string // when set, only calls starting with this fail
}

func (h *reexecing) Run(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	if h.n > 0 && strings.HasPrefix(cmd, "systemctl ") && strings.HasPrefix(cmd, h.only) {
		h.n--
		h.ran = append(h.ran, cmd)
		return ssh.Result{ExitCode: 1, Stderr: []byte(h.stderr + "\n")}, nil
	}
	return h.host.Run(ctx, cmd, stdin)
}

// What systemctl printed while systemd re-executed, on Fedora 45.
var busErrors = []string{
	"Failed to connect to system scope bus via local transport: Connection refused",
	"Failed to get properties: Transport endpoint is not connected",
	"Failed to get properties: Connection reset by peer",
}

func noWait(t *testing.T) {
	t.Helper()
	was := busWait
	busWait = 0
	t.Cleanup(func() { busWait = was })
}

func TestReadRetriesWhileSystemdReexecs(t *testing.T) {
	noWait(t)
	for _, msg := range busErrors {
		h := &reexecing{host: host{show: show("loaded", "active", "enabled", "no")}, n: 3, stderr: msg}
		a, err := Read(ctx, h, "postgresql")
		if err != nil {
			t.Fatalf("%q: %v", msg, err)
		}
		if !a.Running || !a.Enabled {
			t.Fatalf("%q: got %+v", msg, a)
		}
		if len(h.ran) != 4 {
			t.Fatalf("%q: ran %d times, want 3 failures and 1 answer: %q", msg, len(h.ran), h.ran)
		}
	}
}

func TestActionsRetryWhileSystemdReexecs(t *testing.T) {
	noWait(t)
	yes := true
	for _, msg := range busErrors {
		for verb, do := range map[string]func(*reexecing) error{
			"systemctl start":   func(h *reexecing) error { return Apply(ctx, h, Desired{Name: "postgresql", State: Started}) },
			"systemctl enable":  func(h *reexecing) error { return Apply(ctx, h, Desired{Name: "postgresql", Enabled: &yes}) },
			"systemctl restart": func(h *reexecing) error { return Restart(ctx, h, "postgresql") },
		} {
			h := &reexecing{host: host{show: show("loaded", "inactive", "disabled", "no")}, n: 2, stderr: msg, only: verb}
			if err := do(h); err != nil {
				t.Fatalf("%s, %q: %v", verb, msg, err)
			}
			tries := 0
			for _, c := range h.ran {
				if strings.HasPrefix(c, verb) {
					tries++
				}
			}
			if tries != 3 {
				t.Fatalf("%s, %q: tried %d times, want 2 failures and 1 success: %q", verb, msg, tries, h.ran)
			}
		}
	}
}

func TestOtherErrorsAreNotRetried(t *testing.T) {
	noWait(t)
	h := &reexecing{host: host{show: show("loaded", "inactive", "enabled", "no")}, n: 5, stderr: "Job for nginx.service failed because the control process exited with error code."}
	if _, err := Read(ctx, h, "nginx"); err == nil {
		t.Fatal("a real failure was hidden")
	}
	if len(h.ran) != 1 {
		t.Fatalf("ran %d times, want 1: %q", len(h.ran), h.ran)
	}
}

func TestRetryGivesUp(t *testing.T) {
	noWait(t)
	h := &reexecing{host: host{show: show("loaded", "active", "enabled", "no")}, n: 1000, stderr: busErrors[0]}
	_, err := Read(ctx, h, "nginx")
	if err == nil || !strings.Contains(err.Error(), "Failed to connect") {
		t.Fatalf("got %v, want the bus error once retries run out", err)
	}
	if len(h.ran) != busRetries+1 {
		t.Fatalf("ran %d times, want %d", len(h.ran), busRetries+1)
	}
}

func TestRetryStopsWhenCancelled(t *testing.T) {
	was := busWait
	busWait = 1e9 // a second, so cancelling is what ends it
	t.Cleanup(func() { busWait = was })
	h := &reexecing{host: host{show: show("loaded", "active", "enabled", "no")}, n: 1000, stderr: busErrors[0]}
	c, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := Read(c, h, "nginx"); err == nil {
		t.Fatal("a cancelled read succeeded")
	}
	if len(h.ran) != 1 {
		t.Fatalf("ran %d times after cancel, want 1", len(h.ran))
	}
}
