// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// promptPoll is how often startBecome looks at sudo's stderr for its prompt.
const promptPoll = 10 * time.Millisecond

// stderrWait bounds how long startBecome waits for the rest of sudo's
// stderr once the agent has failed to start.
const stderrWait = 2 * time.Second

// startBecome runs the start script through sudo, so the agent runs as
// root, and answers sudo's password prompt.
//
// sudo is given a random prompt, so its prompt can't be mistaken for
// anything else on stderr, and the password goes to stdin only after
// sudo has printed that prompt. A second prompt means sudo rejected the
// password; the process is closed at once instead of letting sudo try
// again. Once the agent says hello, its stdin carries frames and nothing
// else.
func startBecome(ctx context.Context, c *ssh.Client, script string, b *ssh.Become) (*Client, error) {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	marker := []byte("conn3x-sudo-" + hex.EncodeToString(nonce[:]) + ":")
	// sudo's refusals are matched in English.
	p, err := c.Start(ctx, "LC_ALL=C exec sudo -S -p "+ssh.Quote(string(marker))+" -- /bin/sh -c "+ssh.Quote(script))
	if err != nil {
		return nil, fmt.Errorf("starting the agent as root: %w", err)
	}

	type hello struct {
		a   *Client
		err error
	}
	done := make(chan hello, 1)
	go func() {
		a, err := NewClient(ctx, p)
		done <- hello{a, err}
	}()
	// stop closes the process and waits for NewClient to give up.
	stop := func(err error) (*Client, error) {
		p.Close()
		<-done
		return nil, err
	}

	tick := time.NewTicker(promptPoll)
	defer tick.Stop()
	answered := false
	for {
		select {
		case h := <-done:
			if h.err == nil {
				return h.a, nil
			}
			// sudo refusing is an error, as it is in the shell; anything
			// else means this host can't run the agent. The session ending
			// means its stderr has all been copied.
			waited := make(chan struct{})
			go func() { _ = p.Wait(); close(waited) }()
			select {
			case <-waited:
			case <-time.After(stderrWait):
			}
			stderr := p.Stderr()
			if err := ssh.SudoFailure(stderr, c.Addr()); err != nil {
				return nil, err
			}
			if msg := bytes.TrimSpace(stderr); len(msg) > 0 {
				return nil, fmt.Errorf("starting the agent as root: %v: %s", h.err, msg)
			}
			return nil, fmt.Errorf("starting the agent as root: %v", h.err)
		case <-tick.C:
			switch n := bytes.Count(p.Stderr(), marker); {
			case n > 1:
				return stop(ssh.SudoFailure([]byte("incorrect password"), c.Addr()))
			case n == 1 && !answered && len(b.Password) == 0:
				return stop(ssh.SudoFailure([]byte("password is required"), c.Addr()))
			case n == 1 && !answered:
				answered = true
				if _, err := p.Write(append(bytes.Clone(b.Password), '\n')); err != nil {
					return stop(fmt.Errorf("starting the agent as root: sending the sudo password: %w", err))
				}
			}
		}
	}
}
