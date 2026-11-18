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
	"log"
	"os"
	"strconv"
	"sync"

	gossh "golang.org/x/crypto/ssh"
)

// A long-lived shell per session slot runs Run's commands one after another,
// so a command costs one round trip instead of the two and a half a new
// session takes: open the channel, start the command, read the exit. A plan
// over a WAN spends most of its time on those round trips (#524).
//
// Each command goes to the shell's stdin as one line:
//
//	(LC_ALL=C exec /bin/sh -c 'CMD') </dev/null; printf '\n\001NONCE %d\n' $? ...
//
// and its output ends at a marker on stdout, with the exit status, and one on
// stderr. The nonce is random per command, so output can't fake the end of a
// command it doesn't know. The command runs in a subshell with stdin from
// /dev/null, so it can't exit the shell or read the next command.
//
// Only commands without stdin go through a shell; the rest, and anything the
// shell can't run, take a session of their own as before. A command that's
// cancelled, prints past MaxOutput, or ends the shell takes the shell down
// with it, and the next command starts a fresh one.
//
// shortcut: off unless CONN3X_SSH_SHELL=1, until benchmarks on a real fleet
// say it should be the default.

// shellsEnabled reports whether Run may use a long-lived shell.
func shellsEnabled() bool { return os.Getenv("CONN3X_SSH_SHELL") == "1" }

// shell is one long-lived /bin/sh on its own session.
type shell struct {
	session *gossh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	stderr  io.Reader
	// pending holds what was read past the last command's marker, which
	// is nothing unless a command left something writing in the
	// background.
	pendingOut, pendingErr []byte
}

// shells is a Client's pool of idle shells.
type shells struct {
	mu   sync.Mutex
	idle []*shell
	open int  // shells open, idle or busy
	off  bool // the host can't run one; use sessions
	// ready is set once a plain session has worked on the connection, so
	// a server that refuses sessions is found by one, as before.
	ready bool
}

// maxShells is how many of a connection's session slots shells may hold:
// half, leaving the rest for commands with stdin and for Start, and none
// when the server allows a single session.
func (c *Client) maxShells() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.limit / 2
}

// closeIdleShell closes one idle shell, if there is one, so its slot comes
// back for a session.
func (c *Client) closeIdleShell() {
	p := &c.shells
	p.mu.Lock()
	n := len(p.idle)
	if n == 0 {
		p.mu.Unlock()
		return
	}
	sh := p.idle[n-1]
	p.idle = p.idle[:n-1]
	p.mu.Unlock()
	c.dropShell(sh)
}

// trimShells closes idle shells beyond maxShells, which happens when the
// server turns out to allow fewer sessions than the cap: an idle shell holds
// its slot, and a command waiting for one would wait for good.
func (c *Client) trimShells() {
	limit := c.maxShells()
	p := &c.shells
	for {
		p.mu.Lock()
		if p.open <= limit || len(p.idle) == 0 {
			p.mu.Unlock()
			return
		}
		sh := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		p.mu.Unlock()
		c.dropShell(sh)
	}
}

// runInShell runs cmd in an idle shell, or a new one, and reports false when
// none can be had, so the caller uses a session.
func (c *Client) runInShell(ctx context.Context, cmd string) (Result, bool, error) {
	c.trimShells()
	sh, err := c.takeShell(ctx)
	if sh == nil || err != nil {
		return Result{}, false, err
	}
	res, err := sh.run(ctx, cmd)
	if errors.Is(err, errStillWriting) {
		c.dropShell(sh)
		return res, true, nil
	}
	if err != nil {
		c.dropShell(sh)
		if errors.Is(err, errOverOutput) {
			return Result{}, true, c.overOutput()
		}
		if ctx.Err() != nil {
			return Result{}, true, ctx.Err()
		}
		return Result{}, true, fmt.Errorf("ssh %s: %w", c.addr, err)
	}
	limit := c.maxShells()
	c.shells.mu.Lock()
	over := c.shells.open > limit || c.waiting.Load() > 0
	if !over {
		c.shells.idle = append(c.shells.idle, sh)
	}
	c.shells.mu.Unlock()
	if over {
		c.dropShell(sh) // the cap fell while it ran, or a session waits
	}
	return res, true, nil
}

// takeShell returns an idle shell, or opens one when fewer than maxShells
// are open, or returns nil.
func (c *Client) takeShell(ctx context.Context) (*shell, error) {
	p := &c.shells
	p.mu.Lock()
	if p.off || !p.ready {
		p.mu.Unlock()
		return nil, nil
	}
	if n := len(p.idle); n > 0 {
		sh := p.idle[n-1]
		p.idle = p.idle[:n-1]
		p.mu.Unlock()
		return sh, nil
	}
	if p.open >= c.maxShells() {
		p.mu.Unlock()
		return nil, nil
	}
	p.open++
	p.mu.Unlock()

	sh, err := c.openShell(ctx)
	if err != nil {
		p.mu.Lock()
		p.open--
		p.mu.Unlock()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, nil // the caller falls back to a session
	}
	return sh, nil
}

// openShell starts a shell and checks it answers. A host where it doesn't,
// such as one whose login shell is cmd.exe, gets no more tries.
func (c *Client) openShell(ctx context.Context) (*shell, error) {
	// Only a slot that's free now: waiting for one could wait on idle
	// shells, and a session serves the command as well.
	select {
	case c.slots <- struct{}{}:
	default:
		return nil, errNoSlot
	}
	session, err := c.conn.NewSession()
	if err != nil {
		// A server with fewer sessions than the cap: leave finding its
		// limit to the sessions, which do it a slot at a time, and use
		// no more shells here.
		c.release()
		c.shells.mu.Lock()
		c.shells.off = true
		c.shells.mu.Unlock()
		return nil, errNoSlot
	}
	sh := &shell{session: session}
	if sh.stdin, err = session.StdinPipe(); err == nil {
		if sh.stdout, err = session.StdoutPipe(); err == nil {
			if sh.stderr, err = session.StderrPipe(); err == nil {
				err = session.Start("LC_ALL=C exec /bin/sh -s")
			}
		}
	}
	if err == nil {
		var res Result
		if res, err = sh.run(ctx, "true"); err == nil && res.ExitCode != 0 {
			err = fmt.Errorf("exit status %d", res.ExitCode)
		}
	}
	if err != nil {
		c.done(session)
		if ctx.Err() == nil && !errors.Is(err, errNoSlot) {
			c.shells.mu.Lock()
			c.shells.off = true
			c.shells.mu.Unlock()
			log.Printf("[DEBUG] conn3x: %s: no long-lived shell (%v); using a session per command", c.addr, err)
		}
		return nil, err
	}
	return sh, nil
}

// dropShell closes a shell that can't be trusted for another command.
func (c *Client) dropShell(sh *shell) {
	_ = sh.session.Signal(gossh.SIGKILL)
	c.done(sh.session)
	c.shells.mu.Lock()
	c.shells.open--
	c.shells.mu.Unlock()
}

var (
	errOverOutput = errors.New("output over the limit")
	errNoSlot     = errors.New("no free session slot")
	// errStillWriting is a command that finished with something it left
	// running still writing to the shell's output.
	errStillWriting = errors.New("a background process is still writing")
)

// run sends cmd to the shell and reads its output to the markers.
func (sh *shell) run(ctx context.Context, cmd string) (Result, error) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	nonce := hex.EncodeToString(b)
	line := fmt.Sprintf("printf '\\001%s-start\\n'; printf '\\001%s-start\\n' >&2; (LC_ALL=C exec /bin/sh -c %s) </dev/null; printf '\\n\\001%s %%d\\n' $?; printf '\\n\\001%s\\n' >&2\n",
		nonce, nonce, Quote(Prelude+cmd), nonce, nonce)

	type read struct {
		out, rest []byte
		err       error
	}
	outc, errc := make(chan read, 1), make(chan read, 1)
	start := []byte("\x01" + nonce + "-start\n")
	// Anything before a stream's start marker was written by something an
	// earlier command left running; it's dropped, not taken as this
	// command's output.
	stream := func(r io.Reader, pending, end []byte, line bool) read {
		early, rest, err := readTo(r, pending, start, false)
		if err != nil {
			return read{err: err}
		}
		if len(early) > 0 {
			log.Printf("[DEBUG] conn3x: dropped %d bytes a background process wrote after its command ended", len(early))
		}
		out, rest, err := readTo(r, rest, end, line)
		return read{out, rest, err}
	}
	go func() { outc <- stream(sh.stdout, sh.pendingOut, []byte("\n\x01"+nonce+" "), true) }()
	go func() { errc <- stream(sh.stderr, sh.pendingErr, []byte("\n\x01"+nonce+"\n"), false) }()
	if _, err := io.WriteString(sh.stdin, line); err != nil {
		return Result{}, err
	}

	var o, e read
	for got := 0; got < 2; got++ {
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case o = <-outc:
		case e = <-errc:
		}
		if o.err != nil {
			return Result{}, o.err
		}
		if e.err != nil {
			return Result{}, e.err
		}
	}
	// The stdout marker is followed by the exit status and a newline.
	status, rest, ok := bytes.Cut(o.rest, []byte("\n"))
	code, err := strconv.Atoi(string(status))
	if !ok || err != nil {
		return Result{}, fmt.Errorf("unreadable exit status %q", status)
	}
	sh.pendingOut, sh.pendingErr = rest, e.rest
	res := Result{Stdout: o.out, Stderr: e.out, ExitCode: code}
	if len(rest) > 0 || len(e.rest) > 0 {
		// Something the command started is still writing. The output is
		// the command's; the shell isn't safe for the next one.
		return res, errStillWriting
	}
	return res, nil
}

// readTo reads r, after what's in pending, up to marker, and returns what
// came before it and after it. With line set it also reads to the newline
// after the marker. Past MaxOutput it gives up.
func readTo(r io.Reader, pending, marker []byte, line bool) (before, after []byte, err error) {
	buf := append([]byte(nil), pending...)
	chunk := make([]byte, 32*1024)
	for {
		if i := bytes.Index(buf, marker); i >= 0 {
			after = buf[i+len(marker):]
			if !line || bytes.IndexByte(after, '\n') >= 0 {
				if i > MaxOutput {
					return nil, nil, errOverOutput
				}
				return buf[:i], after, nil
			}
		}
		if len(buf) > MaxOutput+len(marker)+32 {
			return nil, nil, errOverOutput
		}
		n, err := r.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if err != nil && n == 0 {
			if err == io.EOF {
				err = errors.New("the shell ended")
			}
			return nil, nil, err
		}
	}
}
