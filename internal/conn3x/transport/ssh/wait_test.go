// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
)

func TestDialWaitRetriesRefusedConnections(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	// Keys exist before the host does, as with a pinned droplet host key.
	keys := sshtest.NewKeys(t)
	addr := "127.0.0.1:" + strconv.Itoa(port)
	go func() {
		time.Sleep(1500 * time.Millisecond)
		sshtest.StartWith(t, addr, keys)
	}()
	cfg := Config{Host: "127.0.0.1", Port: port, User: "test", PrivateKey: keys.ClientKey, KnownHostsFile: keys.KnownHosts(t, addr), Timeout: 2 * time.Second}
	start := time.Now()
	c, err := DialWait(context.Background(), cfg, 15*time.Second)
	if err != nil {
		t.Fatalf("DialWait: %v", err)
	}
	c.Close()
	if time.Since(start) < time.Second {
		t.Fatal("connected before the server existed")
	}
}

func TestDialWaitDoesNotRetryHostKeyErrors(t *testing.T) {
	s := sshtest.New(t)
	empty := filepath.Join(t.TempDir(), "known_hosts")
	_ = os.WriteFile(empty, nil, 0o600)
	cfg := Config{Host: s.Host, Port: s.Port, User: "test", PrivateKey: s.ClientKey, KnownHostsFile: empty}
	start := time.Now()
	_, err := DialWait(context.Background(), cfg, 30*time.Second)
	if !errors.Is(err, ErrHostKey) {
		t.Fatalf("err = %v, want ErrHostKey", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("a host key failure was retried")
	}
}

func TestDialWaitGivesUpAtTheDeadline(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	start := time.Now()
	keys := sshtest.NewKeys(t)
	_, err := DialWait(context.Background(), Config{Host: "127.0.0.1", Port: port, User: "x", PrivateKey: keys.ClientKey,
		KnownHostsFile: keys.KnownHosts(t, "127.0.0.1:"+strconv.Itoa(port)), Timeout: time.Second}, 3*time.Second)
	if err == nil {
		t.Fatal("dial to a closed port succeeded")
	}
	if d := time.Since(start); d < 2*time.Second || d > 6*time.Second {
		t.Fatalf("gave up after %s, want about 3s", d)
	}
}

func TestDialWaitDoesNotRetryABadPrivateKey(t *testing.T) {
	start := time.Now()
	_, err := DialWait(context.Background(), Config{Host: "127.0.0.1", Port: 1, User: "x", PrivateKey: []byte("not a key")}, 30*time.Second)
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("bad key: err = %v after %s; want an immediate error", err, time.Since(start))
	}
}
