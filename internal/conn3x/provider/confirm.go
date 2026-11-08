// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/confirm"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// confirmLimits bound confirm_after: long enough to log in again, short
// enough that a locked-out host doesn't stay locked out for long.
const (
	minConfirmAfter = 10 * time.Second
	maxConfirmAfter = time.Hour
)

func parseConfirmAfter(v cty.Value) (time.Duration, error) {
	s := stringOr(v, "")
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("confirm_after is a duration, such as \"60s\" or \"2m\", not %q", s)
	}
	if d < minConfirmAfter || d > maxConfirmAfter {
		return 0, fmt.Errorf("confirm_after must be between %s and %s, not %s", minConfirmAfter, maxConfirmAfter, d)
	}
	return d, nil
}

// freshLogin dials a new connection, outside the pool, with the step's
// whole ssh block: jump hosts and the host key check included. Logging in
// is the proof a confirm needs.
func freshLogin(ctx context.Context, conn cty.Value) (modules.Runner, func(), error) {
	cfg, err := sshConfig(conn)
	if err != nil {
		return nil, nil, err
	}
	client, err := ssh.Dial(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	closeIt := func() { _ = client.Close() }
	if b := conn.GetAttr("become"); b.IsNull() || !b.True() {
		return client, closeIt, nil
	}
	var password []byte
	if file := stringOr(conn.GetAttr("become_password_file"), ""); file != "" {
		raw, err := os.ReadFile(expandHome(file))
		if err != nil {
			closeIt()
			return nil, nil, fmt.Errorf("reading become_password_file: %w", err)
		}
		password = []byte(strings.TrimRight(string(raw), "\r\n"))
	}
	return &ssh.Become{Client: client, Password: password}, closeIt, nil
}

func newGuardID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// guarded runs change between arming a revert and confirming it over a new
// login. A change or reload that fails reverts at once. When the new login
// doesn't come before the deadline, it waits for the host's own revert and
// says what happened.
func guarded(ctx context.Context, h *hostConn, conn cty.Value, g confirm.Guard, change func() error) error {
	if err := confirm.Arm(ctx, h, g); err != nil {
		return err
	}
	revertNow := func(cause error) error {
		if rerr := confirm.RevertNow(ctx, h, g); rerr != nil {
			return fmt.Errorf("%w; and reverting it failed too, so the host will try again on its own within %s: %v", cause, g.After, rerr)
		}
		return fmt.Errorf("%w; the old state was put back", cause)
	}
	if err := change(); err != nil {
		return revertNow(err)
	}
	if g.Reload != "" {
		if res, err := h.Run(ctx, g.Reload, nil); err != nil || res.ExitCode != 0 {
			why := ""
			if err != nil {
				why = err.Error()
			} else {
				why = fmt.Sprintf("exit status %d: %s", res.ExitCode, strings.TrimSpace(string(res.Stderr)))
			}
			return revertNow(fmt.Errorf("reload failed (%s)", why))
		}
	}

	deadline := time.Now().Add(g.After - 3*time.Second)
	var last error
	for time.Now().Before(deadline) {
		attempt, cancel := context.WithDeadline(ctx, deadline)
		runner, done, err := freshLogin(attempt, conn)
		if err == nil {
			err = confirm.Confirm(attempt, runner, g)
			done()
		}
		cancel()
		if err == nil {
			return nil
		}
		if errors.Is(err, confirm.ErrAlreadyReverted) {
			return fmt.Errorf("logged in again, but too late: %w", err)
		}
		last = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("stopped before confirming, so the host will put the old state back on its own within %s: %w", g.After, ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
	// No new login: let the host's own revert run, then see whether it
	// answers again.
	wait := time.NewTimer(time.Until(deadline.Add(15 * time.Second)))
	select {
	case <-ctx.Done():
		wait.Stop()
		return fmt.Errorf("couldn't log in again over a new connection after the change (%v), and stopped before the host's own revert was due: %w", last, ctx.Err())
	case <-wait.C:
	}
	if _, done, err := freshLogin(ctx, conn); err == nil {
		done()
		return fmt.Errorf("couldn't log in again over a new connection after the change (%v), so the host put the old state back by itself; it answers again now", last)
	}
	return fmt.Errorf("couldn't log in again over a new connection after the change (%v); the host was due to put the old state back by itself, but it still doesn't answer", last)
}
