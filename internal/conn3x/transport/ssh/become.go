// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Become runs commands as root through sudo on top of a Client.
//
// Commands carry data on stdin (file content, for one), so a password must
// never reach a command by mistake. Become first asks whether sudo needs a
// password at all; without one it uses "sudo -n" and sends nothing extra,
// and with one it writes the password as the first line of stdin, where
// "sudo -S" consumes it.
type Become struct {
	Client   *Client
	Password []byte // empty when sudo is NOPASSWD

	once      sync.Once
	needsPass bool
	probeErr  error
}

// Run executes cmd as root. A non-zero exit status of the command itself is
// reported in Result; sudo refusing to run it is an error.
func (b *Become) Run(ctx context.Context, cmd string, stdin []byte) (Result, error) {
	b.once.Do(func() { b.probe(ctx) })
	if b.probeErr != nil {
		return Result{}, b.probeErr
	}

	inner := "/bin/sh -c " + Quote("export LC_ALL=C; "+cmd)
	var res Result
	var err error
	if b.needsPass {
		in := append(append(append([]byte(nil), b.Password...), '\n'), stdin...)
		res, err = b.Client.Run(ctx, "sudo -S -p '' -- "+inner, in)
	} else {
		res, err = b.Client.Run(ctx, "sudo -n -- "+inner, stdin)
	}
	if err != nil {
		return res, err
	}
	if res.ExitCode != 0 {
		if sudoErr := SudoFailure(res.Stderr, b.Client.addr); sudoErr != nil {
			return res, sudoErr
		}
	}
	return res, nil
}

// probe learns whether sudo will ask for a password.
func (b *Become) probe(ctx context.Context) {
	res, err := b.Client.Run(ctx, "sudo -n -- true", nil)
	switch {
	case err != nil:
		b.probeErr = err
	case res.ExitCode == 0:
		b.needsPass = false
	case bytes.Contains(res.Stderr, []byte("password is required")):
		if len(b.Password) == 0 {
			b.probeErr = SudoFailure(res.Stderr, b.Client.addr)
			return
		}
		b.needsPass = true
		// Check the password on its own first. On a wrong password sudo
		// retries by reading more lines from stdin, and those lines must
		// never be command input.
		check, err := b.Client.Run(ctx, "sudo -S -p '' -v", append(append([]byte(nil), b.Password...), '\n'))
		switch {
		case err != nil:
			b.probeErr = err
		case check.ExitCode != 0:
			b.probeErr = SudoFailure(check.Stderr, b.Client.addr)
			if b.probeErr == nil {
				b.probeErr = fmt.Errorf("%w on %s: sudo rejected the password: %s", ErrBecome, b.Client.addr, strings.TrimSpace(string(check.Stderr)))
			}
		}
	default:
		b.probeErr = SudoFailure(res.Stderr, b.Client.addr)
		if b.probeErr == nil {
			b.probeErr = fmt.Errorf("%w on %s: sudo failed: %s", ErrBecome, b.Client.addr, strings.TrimSpace(string(res.Stderr)))
		}
	}
}

// ErrBecome is wrapped by every failure of sudo itself.
var ErrBecome = errors.New("become failed")

// SudoFailure recognizes sudo's own refusals in stderr, and is nil for
// anything else.
func SudoFailure(stderr []byte, addr string) error {
	msg := strings.TrimSpace(string(stderr))
	switch {
	case strings.Contains(msg, "incorrect password"):
		return fmt.Errorf("%w on %s: sudo rejected the password from become_password_file (incorrect password)", ErrBecome, addr)
	case strings.Contains(msg, "must have a tty"):
		return fmt.Errorf("%w on %s: sudo is set to requiretty; allow this user to run sudo without a terminal (Defaults:<user> !requiretty)", ErrBecome, addr)
	case strings.Contains(msg, "is not in the sudoers") || strings.Contains(msg, "not allowed to run sudo"):
		return fmt.Errorf("%w on %s: %s", ErrBecome, addr, msg)
	case strings.Contains(msg, "password is required"):
		return fmt.Errorf("%w on %s: sudo needs a password; set become_password_file in the ssh block", ErrBecome, addr)
	}
	return nil
}
