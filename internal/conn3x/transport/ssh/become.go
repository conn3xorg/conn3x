// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// Become runs commands as root through sudo on top of a Client.
//
// Commands carry data on stdin (file content, for one), so a password must
// never reach a command by mistake. Become first asks whether sudo needs a
// password at all; without one it uses "sudo -n" and sends nothing extra,
// and with one it writes the password to stdin only once "sudo -S" has
// printed its prompt, and the command's input only once the command has
// started.
type Become struct {
	Client   *Client
	Password []byte // empty when sudo is NOPASSWD

	mu        sync.Mutex
	probed    bool
	needsPass bool
	probeErr  error
}

// Run executes cmd as root. A non-zero exit status of the command itself is
// reported in Result; sudo refusing to run it is an error.
func (b *Become) Run(ctx context.Context, cmd string, stdin []byte) (Result, error) {
	if err := b.ready(ctx); err != nil {
		return Result{}, err
	}

	inner := "/bin/sh -c " + Quote(Prelude+cmd)
	var res Result
	var err error
	if b.needsPass {
		res, err = b.runPrompted(ctx, inner, stdin)
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

// promptPoll is how often runPrompted looks at stderr for sudo's prompt
// and the command's start.
const promptPoll = 2 * time.Millisecond

// runPrompted runs inner through "sudo -S" and answers its prompt.
//
// sudo is given a random prompt, and the command prints a second random
// marker to stderr as it starts. The password is written only after the
// prompt, and stdin only after the start marker, so neither can be read by
// the wrong program: a sudoers rule that lets this one command run without
// a password would otherwise leave the password as the command's first line
// of input. A second prompt means sudo rejected the password; the session
// is closed at once, before sudo can read command input as another attempt.
//
// -k makes sudo ignore cached credentials and leave none behind, so a run
// never gives the login user's other sessions a passwordless sudo.
func (b *Become) runPrompted(ctx context.Context, inner string, stdin []byte) (Result, error) {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Result{}, err
	}
	prompt := []byte("conn3x-sudo-" + hex.EncodeToString(nonce[:]) + ":")
	started := []byte("conn3x-run-" + hex.EncodeToString(nonce[:]) + ":")
	// sudo's refusals are matched in English.
	p, err := b.Client.Start(ctx, "LC_ALL=C exec sudo -k -S -p "+Quote(string(prompt))+" -- /bin/sh -c "+
		Quote("printf %s "+Quote(string(started))+" >&2; exec "+inner))
	if err != nil {
		return Result{}, err
	}
	defer p.Close()

	type exit struct {
		stdout []byte
		err    error
		over   bool
	}
	done := make(chan exit, 1)
	go func() {
		// The same limit as exec: past MaxOutput the command is killed.
		out, _ := io.ReadAll(io.LimitReader(p, int64(MaxOutput)+1))
		if len(out) > MaxOutput {
			_ = p.session.Signal(gossh.SIGKILL)
			_ = p.session.Close()
			done <- exit{over: true}
			return
		}
		done <- exit{stdout: out, err: p.session.Wait()}
	}()

	tick := time.NewTicker(promptPoll)
	defer tick.Stop()
	poll := tick.C
	answered := false
	for {
		select {
		case <-ctx.Done():
			_ = p.session.Signal(gossh.SIGKILL)
			return Result{}, ctx.Err()
		case e := <-done:
			if e.over {
				return Result{}, b.Client.overOutput()
			}
			// What sudo wrote comes before the start marker; the command's
			// own stderr is what follows it.
			stderr := p.Stderr()
			if _, after, ok := bytes.Cut(stderr, started); ok {
				stderr = after
			} else {
				stderr = bytes.ReplaceAll(stderr, prompt, nil)
			}
			res := Result{Stdout: e.stdout, Stderr: stderr}
			var exitErr *gossh.ExitError
			switch {
			case e.err == nil:
				return res, nil
			case errors.As(e.err, &exitErr):
				res.ExitCode = exitErr.ExitStatus()
				return res, nil
			default:
				return res, fmt.Errorf("ssh %s: %w", b.Client.addr, e.err)
			}
		case <-poll:
			seen := p.Stderr()
			switch n := bytes.Count(seen, prompt); {
			case bytes.Contains(seen, started):
				poll = nil
				// The command may exit without reading its input, and a
				// large input may block: neither should hold up the loop.
				go func() {
					_, _ = p.stdin.Write(stdin)
					_ = p.stdin.Close()
				}()
			case n > 1:
				return Result{}, SudoFailure([]byte("incorrect password"), b.Client.addr)
			case n == 1 && !answered:
				answered = true
				if _, err := p.stdin.Write(append(bytes.Clone(b.Password), '\n')); err != nil {
					return Result{}, fmt.Errorf("ssh %s: sending the sudo password: %w", b.Client.addr, err)
				}
			}
		}
	}
}

// ready probes sudo on the first Run. The answer holds for the life of the
// connection, except a probe cut short by its context, which the next Run
// tries again.
func (b *Become) ready(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.probed {
		return b.probeErr
	}
	b.probeErr = nil
	b.probe(ctx)
	if err := b.probeErr; errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	b.probed = true
	return b.probeErr
}

// probe learns whether sudo will ask for a password. It asks about
// /bin/sh, the command Run hands sudo, so a NOPASSWD rule for it counts.
func (b *Become) probe(ctx context.Context) {
	res, err := b.Client.Run(ctx, "sudo -n -- /bin/sh -c true", nil)
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
