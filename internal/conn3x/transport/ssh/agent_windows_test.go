// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh/agent"
)

// An agent on a named pipe, as Windows' own OpenSSH agent runs, hands over
// its keys; a pipe nobody listens on says how to start the agent.
func TestDialAgentOverANamedPipe(t *testing.T) {
	pipe := fmt.Sprintf(`\\.\pipe\conn3x-test-agent-%d`, os.Getpid())
	l, err := winio.ListenPipe(pipe, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: key}); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(keyring, c); c.Close() }()
		}
	}()

	conn, err := dialAgent(pipe)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	keys, err := agent.NewClient(conn).List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys = %v, err = %v", keys, err)
	}

	if _, err := dialAgent(`\\.\pipe\conn3x-nobody-listens`); err == nil || !strings.Contains(err.Error(), "connecting to the SSH agent") {
		t.Errorf("err = %v", err)
	}
}
