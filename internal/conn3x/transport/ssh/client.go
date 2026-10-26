// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package ssh runs commands on managed hosts over one SSH connection per
// host. Host keys are always verified; there is no way to turn that off.
package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ErrHostKey is wrapped by every host key verification failure.
var ErrHostKey = errors.New("host key verification failed")

// Config describes how to reach and authenticate to a host.
type Config struct {
	Host           string
	Port           int // default 22
	User           string
	PrivateKey     []byte // PEM; empty means use the agent at SSH_AUTH_SOCK
	HostKey        string // optional pinned key, in authorized_keys format
	KnownHostsFile string // default ~/.ssh/known_hosts when HostKey is empty
	Timeout        time.Duration
	// Jumps are hosts to connect through first, in order, like ssh -J. Each
	// is checked against KnownHostsFile and uses the same key unless it has
	// its own.
	Jumps []Jump
}

// Jump is a host to connect through on the way to the target.
type Jump struct {
	Host string
	Port int    // default 22
	User string // default the target's user
	// PrivateKey is this hop's own key, PEM; empty means the target's.
	PrivateKey []byte
}

// ParseJump reads a jump host the way ssh -J writes one: [user@]host[:port],
// with IPv6 addresses in brackets.
func ParseJump(s string) (Jump, error) {
	j := Jump{Port: 22}
	rest := s
	if user, host, ok := strings.Cut(s, "@"); ok {
		j.User, rest = user, host
	}
	host, portText, err := net.SplitHostPort(rest)
	if err != nil {
		host, portText = strings.Trim(rest, "[]"), ""
	}
	if portText != "" {
		p, err := strconv.Atoi(portText)
		if err != nil || p < 1 || p > 65535 {
			return Jump{}, fmt.Errorf("jump host %q: port must be between 1 and 65535", s)
		}
		j.Port = p
	}
	if host == "" || strings.ContainsAny(host, " \t/") || (j.User == "" && strings.Contains(s, "@")) {
		return Jump{}, fmt.Errorf("jump host %q must look like [user@]host[:port]", s)
	}
	j.Host = host
	return j, nil
}

// Result is the outcome of one command.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Client is an open connection to one host. It is safe for concurrent use;
// each Run gets its own session on the shared connection. Sessions beyond
// the cap wait their turn rather than fail.
type Client struct {
	addr  string
	conn  *gossh.Client
	jumps []*gossh.Client // the hops in front of conn, outermost first

	slots   chan struct{} // holds a token for each session open
	timeout time.Duration // for a keepalive's reply; see keepalive

	mu       sync.Mutex
	limit    int  // slots still in use; see shrink
	reported int  // the limit last logged
	closed   int  // sessions closed but not yet given back; see done
	pinging  bool // a goroutine is giving them back
}

// defaultMaxSessions caps the sessions open at once on one connection.
// sshd's MaxSessions defaults to 10 and refuses the eleventh. 8 keeps two
// spare, for a session that is still closing when the next opens, such as
// one cancelled while its command was being killed. A server set lower is
// found by being refused; see session.
const defaultMaxSessions = 8

// maxSessions is the cap, from CONN3X_SSH_MAX_SESSIONS when that is set.
func maxSessions() int {
	v := os.Getenv("CONN3X_SSH_MAX_SESSIONS")
	if v == "" {
		return defaultMaxSessions
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 1000 {
		log.Printf("[WARN] conn3x: CONN3X_SSH_MAX_SESSIONS=%q is not a number from 1 to 1000; using %d", v, defaultMaxSessions)
		return defaultMaxSessions
	}
	return n
}

// newClient wraps an authenticated connection.
func newClient(addr string, conn *gossh.Client, jumps []*gossh.Client) *Client {
	n := maxSessions()
	return &Client{addr: addr, conn: conn, jumps: jumps, slots: make(chan struct{}, n), timeout: keepaliveTimeout, limit: n, reported: n}
}

// session waits for a free slot and opens a session in it. The caller
// gives it back with c.done.
//
// A server that allows fewer sessions than the cap refuses the open with
// "open failed". The cap for this connection then drops to the sessions
// already open, and the open waits for one of them to finish and tries
// again. Nothing has run yet, so trying again can't run a command twice;
// it stops once the cap is down to one session.
func (c *Client) session(ctx context.Context) (*gossh.Session, error) {
	for {
		if err := c.acquire(ctx); err != nil {
			return nil, err
		}
		s, err := c.conn.NewSession()
		if err == nil {
			c.mu.Lock()
			if c.limit < c.reported {
				c.reported = c.limit
				log.Printf("[INFO] conn3x: %s refused a session; opening at most %d at once", c.addr, c.limit)
			}
			c.mu.Unlock()
			return s, nil
		}
		if !tooManySessions(err) || !c.shrink() {
			c.release()
			return nil, fmt.Errorf("ssh %s: opening session: %w", c.addr, err)
		}
	}
}

func (c *Client) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err // select would pick a free slot half the time
	}
	select {
	case c.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) release() { <-c.slots }

// keepaliveTimeout is how long a keepalive waits for the server to answer,
// for connections made after it is set.
var keepaliveTimeout = 30 * time.Second

// done closes a session and frees its slot once the server has freed it
// too. sshd counts a session against MaxSessions until it has read the
// client's close and cleaned up, so a new session opened at once can be
// refused. A reply to a request sent after the close proves sshd is past
// it; waiting for that happens in the background, so the caller doesn't.
//
// Keepalives that want a reply go out one at a time, so one per session
// would free slots a round trip apart. Instead one keepalive frees every
// session closed before it was sent.
func (c *Client) done(s *gossh.Session) {
	_ = s.Close()
	c.mu.Lock()
	c.closed++
	start := !c.pinging
	c.pinging = true
	c.mu.Unlock()
	if start {
		go c.ping()
	}
}

// ping frees closed sessions' slots, a keepalive round trip at a time,
// until there are none left.
func (c *Client) ping() {
	for {
		c.mu.Lock()
		n := c.closed
		c.closed = 0
		if n == 0 {
			c.pinging = false
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
		c.keepalive()
		for ; n > 0; n-- {
			c.release()
		}
	}
}

// keepalive waits for the server to answer a keepalive. A server that
// hasn't answered within c.timeout is taken for gone: the connection is
// closed, so the pool dials a new one and commands waiting for a slot
// fail rather than hang.
func (c *Client) keepalive() {
	answered := make(chan struct{})
	go func() {
		_, _, _ = c.conn.SendRequest("keepalive@openssh.com", true, nil)
		close(answered)
	}()
	select {
	case <-answered:
	case <-time.After(c.timeout):
		log.Printf("[WARN] conn3x: %s did not answer a keepalive in %s; closing the connection", c.addr, c.timeout)
		_ = c.Close()
		<-answered
	}
}

// shrink lowers the cap after the server refused a session: the slot the
// caller holds and every free one go out of use for good, leaving one per
// session still open. It reports false, changing nothing, when the cap is
// already one.
func (c *Client) shrink() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.limit <= 1 {
		return false
	}
	c.limit--
	for free := true; free && c.limit > 1; {
		select {
		case c.slots <- struct{}{}:
			c.limit--
		default:
			free = false
		}
	}
	log.Printf("[DEBUG] conn3x: %s refused a session; opening at most %d at once", c.addr, c.limit)
	return true
}

// tooManySessions recognizes sshd refusing a session at MaxSessions.
func tooManySessions(err error) bool {
	var open *gossh.OpenChannelError
	return errors.As(err, &open) && open.Reason == gossh.ConnectionFailed && open.Message == "open failed"
}

// Dial connects and authenticates, verifying the host key first.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	auth, err := authMethod(cfg)
	if err != nil {
		return nil, fmt.Errorf("ssh %s: %w", net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)), err)
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	// Each hop is reached through the one before it; the last is the target.
	hops := make([]Config, 0, len(cfg.Jumps)+1)
	for _, j := range cfg.Jumps {
		hop := Config{Host: j.Host, Port: j.Port, User: j.User, PrivateKey: j.PrivateKey, KnownHostsFile: cfg.KnownHostsFile}
		if hop.Port == 0 {
			hop.Port = 22
		}
		if hop.User == "" {
			hop.User = cfg.User
		}
		hops = append(hops, hop)
	}
	hops = append(hops, cfg)

	var via []*gossh.Client
	closeAll := func() {
		for i := len(via) - 1; i >= 0; i-- {
			via[i].Close()
		}
	}
	for i, hop := range hops {
		addr := net.JoinHostPort(hop.Host, strconv.Itoa(hop.Port))
		hostKeyCallback, algorithms, err := hostKeyCheck(hop, addr)
		if err != nil {
			closeAll()
			return nil, err
		}
		hopAuth := auth
		if i < len(cfg.Jumps) && len(hop.PrivateKey) > 0 {
			if hopAuth, err = authMethod(hop); err != nil {
				closeAll()
				return nil, fmt.Errorf("ssh %s: %w", addr, err)
			}
		}
		var raw net.Conn
		if len(via) == 0 {
			raw, err = (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		} else {
			raw, err = via[len(via)-1].DialContext(ctx, "tcp", addr)
		}
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("ssh %s: %w", addr, err)
		}
		deadline, _ := ctx.Deadline()
		_ = raw.SetDeadline(deadline)
		conn, chans, reqs, err := gossh.NewClientConn(raw, addr, &gossh.ClientConfig{
			User:              hop.User,
			Auth:              []gossh.AuthMethod{hopAuth},
			HostKeyCallback:   hostKeyCallback,
			HostKeyAlgorithms: algorithms,
			Timeout:           cfg.Timeout,
		})
		if err != nil {
			raw.Close()
			closeAll()
			return nil, fmt.Errorf("ssh %s: %w", addr, err)
		}
		_ = raw.SetDeadline(time.Time{})
		via = append(via, gossh.NewClient(conn, chans, reqs))
	}
	target := via[len(via)-1]
	return newClient(net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)), target, via[:len(via)-1]), nil
}

// hostKeyCheck returns the verification callback and, for known_hosts, the
// key algorithms recorded for this host so the server offers a key we can
// actually check rather than one we have no record of.
func hostKeyCheck(cfg Config, addr string) (gossh.HostKeyCallback, []string, error) {
	if cfg.HostKey != "" {
		pinned, _, _, _, err := gossh.ParseAuthorizedKey([]byte(cfg.HostKey))
		if err != nil {
			return nil, nil, fmt.Errorf("%w: host_key for %s is not a valid public key: %v", ErrHostKey, addr, err)
		}
		return func(_ string, _ net.Addr, key gossh.PublicKey) error {
			if !bytes.Equal(key.Marshal(), pinned.Marshal()) {
				return fmt.Errorf("%w: %s presented a %s key that does not match the pinned host_key", ErrHostKey, addr, key.Type())
			}
			return nil
		}, []string{pinned.Type()}, nil
	}

	file, check, err := knownHosts(cfg, addr)
	if err != nil {
		return nil, nil, err
	}

	var algorithms []string
	for _, k := range recorded(check, addr) {
		algorithms = append(algorithms, algorithmsFor(k.Type())...)
	}

	return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		err := check(hostname, remote, key)
		var ke *knownhosts.KeyError
		switch {
		case err == nil:
			return nil
		case errors.As(err, &ke) && len(ke.Want) == 0:
			return fmt.Errorf("%w: %s is not in %s; verify its key and add it, for example with ssh-keyscan", ErrHostKey, addr, file)
		case errors.As(err, &ke):
			return fmt.Errorf("%w: the host key for %s changed since it was recorded in %s", ErrHostKey, addr, file)
		default:
			return fmt.Errorf("%w: %s: %v", ErrHostKey, addr, err)
		}
	}, algorithms, nil
}

// KnownKeys returns the host keys cfg's target is trusted with: its pinned
// host_key, or the keys its known_hosts file records for its address. None
// means the address isn't recorded.
func KnownKeys(cfg Config) ([]gossh.PublicKey, error) {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.HostKey != "" {
		pinned, _, _, _, err := gossh.ParseAuthorizedKey([]byte(cfg.HostKey))
		if err != nil {
			return nil, err
		}
		return []gossh.PublicKey{pinned}, nil
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	_, check, err := knownHosts(cfg, addr)
	if err != nil {
		return nil, err
	}
	return recorded(check, addr), nil
}

func knownHosts(cfg Config, addr string) (string, gossh.HostKeyCallback, error) {
	file := cfg.KnownHostsFile
	if file == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", nil, fmt.Errorf("%w: no known_hosts file and no home directory: %v", ErrHostKey, err)
		}
		file = filepath.Join(home, ".ssh", "known_hosts")
	}
	check, err := knownhosts.New(file)
	if err != nil {
		return "", nil, fmt.Errorf("%w: cannot read known_hosts file %s for %s: %v", ErrHostKey, file, addr, err)
	}
	return file, check, nil
}

// recorded asks check about a key no host has, so it answers with the keys
// it does have for addr.
func recorded(check gossh.HostKeyCallback, addr string) []gossh.PublicKey {
	var keys []gossh.PublicKey
	var keyErr *knownhosts.KeyError
	if err := check(addr, &net.TCPAddr{IP: net.IPv4zero}, probeKey{}); errors.As(err, &keyErr) {
		for _, k := range keyErr.Want {
			keys = append(keys, k.Key)
		}
	}
	return keys
}

// algorithmsFor lists the signature algorithms a host key type can use.
func algorithmsFor(keyType string) []string {
	if keyType == gossh.KeyAlgoRSA {
		return []string{gossh.KeyAlgoRSASHA512, gossh.KeyAlgoRSASHA256, gossh.KeyAlgoRSA}
	}
	return []string{keyType}
}

// probeKey never matches anything; checking it reveals which keys are known.
type probeKey struct{}

func (probeKey) Type() string                          { return "conn3x-probe" }
func (probeKey) Marshal() []byte                       { return []byte("conn3x-probe") }
func (probeKey) Verify([]byte, *gossh.Signature) error { return errors.New("probe key") }

func authMethod(cfg Config) (gossh.AuthMethod, error) {
	if len(cfg.PrivateKey) > 0 {
		signer, err := gossh.ParsePrivateKey(cfg.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("parsing private_key: %w", err)
		}
		return gossh.PublicKeys(signer), nil
	}
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, errors.New("no private_key given and no SSH agent (SSH_AUTH_SOCK is not set)")
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("connecting to the SSH agent: %w", err)
	}
	return gossh.PublicKeysCallback(agent.NewClient(conn).Signers), nil
}

// Run executes cmd with /bin/sh in the C locale, feeding it stdin. A non-zero
// exit status is reported in Result, not as an error.
func (c *Client) Run(ctx context.Context, cmd string, stdin []byte) (Result, error) {
	session, err := c.session(ctx)
	if err != nil {
		return Result{}, err
	}
	defer c.done(session)

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	session.Stdin = bytes.NewReader(stdin)

	if err := session.Start("LC_ALL=C exec /bin/sh -c " + Quote("export LC_ALL=C; "+cmd)); err != nil {
		return Result{}, fmt.Errorf("ssh %s: starting command: %w", c.addr, err)
	}
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()

	select {
	case <-ctx.Done():
		_ = session.Signal(gossh.SIGKILL)
		session.Close()
		return Result{}, ctx.Err()
	case err := <-done:
		res := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
		var exitErr *gossh.ExitError
		switch {
		case err == nil:
			return res, nil
		case errors.As(err, &exitErr):
			res.ExitCode = exitErr.ExitStatus()
			return res, nil
		default:
			return res, fmt.Errorf("ssh %s: %w", c.addr, err)
		}
	}
}

// Process is a command started with Start. Reading reads its stdout and
// writing writes its stdin.
type Process struct {
	addr    string
	session *gossh.Session
	done    func() // closes the session and gives its slot back, once
	stdin   io.WriteCloser
	stdout  io.Reader
	stderr  syncBuffer
}

// Start runs cmd as given, without a PTY, and leaves its stdin and stdout
// open for the caller. Unlike Run it adds no shell or locale around cmd.
func (c *Client) Start(ctx context.Context, cmd string) (*Process, error) {
	session, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	p := &Process{addr: c.addr, session: session, done: sync.OnceFunc(func() { c.done(session) })}
	session.Stderr = &p.stderr
	if p.stdin, err = session.StdinPipe(); err == nil {
		p.stdout, err = session.StdoutPipe()
	}
	if err == nil {
		err = session.Start(cmd)
	}
	if err != nil {
		p.done()
		return nil, fmt.Errorf("ssh %s: starting command: %w", c.addr, err)
	}
	return p, nil
}

func (p *Process) Read(b []byte) (int, error)  { return p.stdout.Read(b) }
func (p *Process) Write(b []byte) (int, error) { return p.stdin.Write(b) }

// Stderr is a snapshot of everything the command has written to stderr so
// far. Nothing signals new output; a caller waiting for some, such as a
// sudo prompt, has to call it again.
func (p *Process) Stderr() []byte { return p.stderr.Bytes() }

// Wait waits for the command to exit. A non-zero exit is an error.
func (p *Process) Wait() error {
	if err := p.session.Wait(); err != nil {
		return fmt.Errorf("ssh %s: %w", p.addr, err)
	}
	return nil
}

// Close ends the command's stdin and the session, freeing its slot.
func (p *Process) Close() error {
	_ = p.stdin.Close()
	err := p.session.Close()
	p.done()
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// syncBuffer is a bytes.Buffer safe to write and read at the same time.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buf.Bytes())
}

// Addr is the host and port the client is connected to.
func (c *Client) Addr() string { return c.addr }

// Alive reports whether the connection still answers a keepalive.
func (c *Client) Alive() bool {
	_, _, err := c.conn.SendRequest("keepalive@openssh.com", true, nil)
	return err == nil
}

// Close ends the connection, and those to any jump hosts.
func (c *Client) Close() error {
	err := c.conn.Close()
	for i := len(c.jumps) - 1; i >= 0; i-- {
		c.jumps[i].Close()
	}
	return err
}

// Quote returns s as one POSIX shell word, safe to splice into a command.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
