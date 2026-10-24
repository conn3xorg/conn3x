// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package sshtest runs an in-process SSH server for tests. It executes
// each command with the local sh, so tests exercise real shell behaviour.
package sshtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Server is an in-process SSH server that runs each exec request with the
// local sh, in its own working directory.
type Server struct {
	Addr      string
	Host      string
	Port      int
	HostKey   gossh.PublicKey
	ClientKey []byte // PEM private key the server accepts
	Dir       string
}

// New starts a server that stops when the test ends.
func New(t testing.TB) *Server {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, err := gossh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	_, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientSigner, _ := gossh.NewSignerFromKey(clientPriv)
	pemBlock, err := gossh.MarshalPrivateKey(clientPriv, "")
	if err != nil {
		t.Fatal(err)
	}

	cfg := &gossh.ServerConfig{
		PublicKeyCallback: func(_ gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			if string(key.Marshal()) == string(clientSigner.PublicKey().Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unknown key")
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	host, port := splitAddr(t, ln.Addr().String())
	s := &Server{
		Addr:      ln.Addr().String(),
		Host:      host,
		Port:      port,
		HostKey:   hostSigner.PublicKey(),
		ClientKey: pemEncode(pemBlock),
		Dir:       t.TempDir(),
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn, cfg)
		}
	}()
	return s
}

func (s *Server) serve(conn net.Conn, cfg *gossh.ServerConfig) {
	_, chans, reqs, err := gossh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	go gossh.DiscardRequests(reqs)
	for ch := range chans {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(gossh.UnknownChannelType, "only sessions")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		go s.session(channel, requests)
	}
}

func (s *Server) session(ch gossh.Channel, reqs <-chan *gossh.Request) {
	defer ch.Close()
	for req := range reqs {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		cmdLen := binary.BigEndian.Uint32(req.Payload[:4])
		command := string(req.Payload[4 : 4+cmdLen])
		_ = req.Reply(true, nil)

		cmd := exec.Command("sh", "-c", command)
		cmd.Dir = s.Dir
		cmd.Stdin = ch
		cmd.Stdout = ch
		cmd.Stderr = ch.Stderr()
		code := 0
		if err := cmd.Run(); err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				code = exit.ExitCode()
			} else {
				code = 255
			}
		}
		status := make([]byte, 4)
		binary.BigEndian.PutUint32(status, uint32(code))
		_, _ = ch.SendRequest("exit-status", false, status)
		return
	}
}

// KnownHosts writes a known_hosts file trusting the server and returns its path.
func (s *Server) KnownHosts(t testing.TB) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	line := KnownHostsLine(s.Addr, s.HostKey)
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// KeyFile writes the client private key to a file and returns its path.
func (s *Server) KeyFile(t testing.TB) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, s.ClientKey, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func splitAddr(t testing.TB, addr string) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", p)
	if err != nil {
		t.Fatal(err)
	}
	return h, port
}

func pemEncode(b *pem.Block) []byte { return pem.EncodeToMemory(b) }

// KnownHostsLine formats a known_hosts entry for addr.
func KnownHostsLine(addr string, key gossh.PublicKey) string {
	return knownhosts.Line([]string{knownhosts.Normalize(addr)}, key)
}
