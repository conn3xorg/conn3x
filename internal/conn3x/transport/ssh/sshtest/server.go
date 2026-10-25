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
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	// Env is added to the environment of every command the server runs.
	Env []string
	// Latency delays every write the server makes, to stand in for a
	// distant host.
	Latency time.Duration

	mu       sync.Mutex
	commands []string

	accepts  atomic.Int64
	forwards atomic.Int64
}

// Commands are the commands the server has run, in order.
func (s *Server) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.commands)
}

// slowConn delays each write by the server's Latency.
type slowConn struct {
	net.Conn
	s *Server
}

func (c slowConn) Write(b []byte) (int, error) {
	time.Sleep(c.s.Latency)
	return c.Conn.Write(b)
}

// Forwards is how many connections the server has forwarded as a jump host.
func (s *Server) Forwards() int64 { return s.forwards.Load() }

// Accepts is how many TCP connections the server has accepted.
func (s *Server) Accepts() int64 { return s.accepts.Load() }

// Keys are the host key and the client key a test server uses. Creating
// them first lets a test know a host's key before the host exists.
type Keys struct {
	Host      gossh.Signer
	ClientKey []byte // PEM private key the server accepts
	client    gossh.PublicKey
}

// NewKeys generates a host key and a client key.
func NewKeys(t testing.TB) Keys {
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
	return Keys{Host: hostSigner, ClientKey: pemEncode(pemBlock), client: clientSigner.PublicKey()}
}

// Sharing returns these keys accepting other's client key instead, for a
// bastion and the hosts behind it that trust the same key.
func (k Keys) Sharing(other Keys) Keys {
	k.ClientKey, k.client = other.ClientKey, other.client
	return k
}

// KnownHosts writes a known_hosts file trusting these keys at addr.
func (k Keys) KnownHosts(t testing.TB, addr string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(KnownHostsLine(addr, k.Host.PublicKey())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// New starts a server on a free port; it stops when the test ends.
func New(t testing.TB) *Server {
	t.Helper()
	return StartWith(t, "127.0.0.1:0", NewKeys(t))
}

// StartWith starts a server on addr with the given keys.
func StartWith(t testing.TB, addr string, keys Keys) *Server {
	t.Helper()
	cfg := &gossh.ServerConfig{
		PublicKeyCallback: func(_ gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			if string(key.Marshal()) == string(keys.client.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unknown key")
		},
	}
	cfg.AddHostKey(keys.Host)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	host, port := splitAddr(t, ln.Addr().String())
	s := &Server{
		Addr:      ln.Addr().String(),
		Host:      host,
		Port:      port,
		HostKey:   keys.Host.PublicKey(),
		ClientKey: keys.ClientKey,
		Dir:       t.TempDir(),
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.accepts.Add(1)
			go s.serve(slowConn{conn, s}, cfg)
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
		if ch.ChannelType() == "direct-tcpip" {
			go s.forward(ch)
			continue
		}
		if ch.ChannelType() != "session" {
			_ = ch.Reject(gossh.UnknownChannelType, "only sessions and forwarding")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		go s.session(channel, requests)
	}
}

// forward connects a direct-tcpip channel to its target, the way a jump
// host does for ssh -J.
func (s *Server) forward(nc gossh.NewChannel) {
	var target struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}
	if err := gossh.Unmarshal(nc.ExtraData(), &target); err != nil {
		_ = nc.Reject(gossh.ConnectionFailed, "bad forward request")
		return
	}
	conn, err := net.Dial("tcp", net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port))))
	if err != nil {
		_ = nc.Reject(gossh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		conn.Close()
		return
	}
	s.forwards.Add(1)
	go gossh.DiscardRequests(reqs)
	go func() { _, _ = io.Copy(ch, conn); _ = ch.CloseWrite() }()
	_, _ = io.Copy(conn, ch)
	conn.Close()
	ch.Close()
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
		s.mu.Lock()
		s.commands = append(s.commands, command)
		s.mu.Unlock()

		cmd := exec.Command("sh", "-c", command)
		cmd.Dir = s.Dir
		cmd.Env = append(os.Environ(), s.Env...)
		// Stdin goes through an os.Pipe so that, as with sshd, the command
		// can exit without waiting for the client to close its stdin.
		stdin, feed, err := os.Pipe()
		if err != nil {
			return
		}
		go func() { _, _ = io.Copy(feed, ch); feed.Close() }()
		cmd.Stdin = stdin
		cmd.Stdout = ch
		cmd.Stderr = ch.Stderr()
		code := 0
		err = cmd.Run()
		stdin.Close()
		if err != nil {
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

// fakeSudo behaves like sudo for the modes the tests need, chosen with
// FAKE_SUDO: "nopasswd", "password:<secret>" or "requiretty". It runs the
// command after "--" and records how it was invoked.
const fakeSudoScript = `#!/bin/sh
nonint=0; stdin=0
while [ $# -gt 0 ]; do
  case "$1" in
    -n) nonint=1; shift ;;
    -S) stdin=1; shift ;;
    -k) shift ;;
    -v) validate=1; shift ;;
    -p) shift 2 ;;
    --) shift; break ;;
    *) break ;;
  esac
done
case "$FAKE_SUDO" in
  requiretty) echo "sudo: sorry, you must have a tty to run sudo" >&2; exit 1 ;;
  nopasswd) ;;
  password:*)
    want=${FAKE_SUDO#password:}
    if [ $nonint = 1 ]; then echo "sudo: a password is required" >&2; exit 1; fi
    # Like real sudo, read up to three password attempts from stdin.
    tries=0
    while [ $tries -lt 3 ]; do
      IFS= read -r got || break
      [ -n "$FAKE_SUDO_LOG" ] && printf '%s\n' "$got" >> "$FAKE_SUDO_LOG"
      [ "$got" = "$want" ] && break
      tries=$((tries + 1))
    done
    if [ "$got" != "$want" ]; then echo "sudo: $tries incorrect password attempts" >&2; exit 1; fi ;;
esac
[ "${validate:-0}" = 1 ] && exit 0
SUDO_USER=fake exec "$@"
`

// FakeSudo puts a fake sudo first on the PATH of every command the server
// runs. mode is "nopasswd", "password:<secret>" or "requiretty".
func (s *Server) FakeSudo(t testing.TB, mode string) {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "sudo"), []byte(fakeSudoScript), 0o755); err != nil {
		t.Fatal(err)
	}
	s.Env = append(s.Env, "PATH="+bin+":"+os.Getenv("PATH"), "FAKE_SUDO="+mode)
}
