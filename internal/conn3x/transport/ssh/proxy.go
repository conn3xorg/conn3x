// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// ExpandProxyCommand fills in OpenSSH's ProxyCommand tokens: %h the host,
// %p the port, %r the user and %% a percent sign. Any other token is an
// error, so a typo doesn't reach the command.
func ExpandProxyCommand(args []string, host string, port int, user string) ([]string, error) {
	// As OpenSSH 9.6 does (CVE-2023-51385): a host or user from an
	// inventory that starts with - would reach the command as an option.
	for what, v := range map[string]string{"host": host, "user": user} {
		if strings.HasPrefix(v, "-") || strings.ContainsFunc(v, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
			return nil, fmt.Errorf("proxy_command can't take the %s %q: it starts with - or holds whitespace or a control character", what, v)
		}
	}
	out := make([]string, len(args))
	for i, a := range args {
		var b strings.Builder
		for j := 0; j < len(a); j++ {
			if a[j] != '%' {
				b.WriteByte(a[j])
				continue
			}
			if j+1 == len(a) {
				return nil, fmt.Errorf("proxy_command argument %q ends with a lone %%; write %%%% for a percent sign", a)
			}
			j++
			switch a[j] {
			case 'h':
				b.WriteString(host)
			case 'p':
				b.WriteString(strconv.Itoa(port))
			case 'r':
				b.WriteString(user)
			case '%':
				b.WriteByte('%')
			default:
				return nil, fmt.Errorf("proxy_command argument %q has %%%c, and only %%h, %%p, %%r and %%%% are known", a, a[j])
			}
		}
		out[i] = b.String()
	}
	return out, nil
}

// SplitProxyCommand splits an ssh_config ProxyCommand line into arguments
// the way a shell would for simple words and quotes, without running a
// shell: no variables, globs, pipes or redirections. A line that needs
// any of those is refused.
func SplitProxyCommand(line string) ([]string, error) {
	var args []string
	var cur strings.Builder
	inWord, quote := false, byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote, inWord = c, true
		case c == ' ' || c == '\t':
			if inWord {
				args, inWord = append(args, cur.String()), false
				cur.Reset()
			}
		case strings.IndexByte("|&;<>()$`\\*?[]{}~", c) >= 0:
			return nil, fmt.Errorf("ProxyCommand %q uses %q, which needs a shell; Conn3x runs the command directly, so write it as plain words and quotes", line, string(c))
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("ProxyCommand %q has an unclosed quote", line)
	}
	if inWord {
		args = append(args, cur.String())
	}
	if len(args) == 0 {
		return nil, errors.New("ProxyCommand is empty")
	}
	return args, nil
}

// proxyConn is an SSH connection over a command's stdin and stdout, as
// OpenSSH's ProxyCommand: the command reaches the host its own way, such
// as aws ssm start-session or gcloud compute start-iap-tunnel.
type proxyConn struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr *bytes.Buffer

	mu    sync.Mutex
	timer *time.Timer
	once  sync.Once
}

// dialProxy starts args, which must already be expanded. It isn't tied to
// a context: the connection outlives the dial, and Close ends it.
func dialProxy(args []string) (*proxyConn, error) {
	cmd := exec.Command(args[0], args[1:]...)
	ownGroup(cmd)
	// A child holding stderr open can't make Wait hang once the proxy is
	// killed.
	cmd.WaitDelay = time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr := &bytes.Buffer{}
	cmd.Stderr = &limitedWriter{w: stderr, n: 4096}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting proxy_command %s: %w", args[0], err)
	}
	return &proxyConn{cmd: cmd, stdin: stdin, stdout: stdout, stderr: stderr}, nil
}

func (p *proxyConn) Read(b []byte) (int, error)  { return p.stdout.Read(b) }
func (p *proxyConn) Write(b []byte) (int, error) { return p.stdin.Write(b) }

// Close ends the command and whatever it started. It's killed, since a
// proxy such as the SSM plugin may not exit on its own when its stdin
// closes.
func (p *proxyConn) Close() error {
	p.once.Do(func() {
		_ = p.stdin.Close()
		killTree(p.cmd)
		_ = p.cmd.Wait()
	})
	return nil
}

// Stderr is what the command printed on stderr, for an error message.
func (p *proxyConn) Stderr() string {
	return strings.TrimSpace(p.stderr.String())
}

type proxyAddr struct{}

func (proxyAddr) Network() string { return "proxy" }
func (proxyAddr) String() string  { return "proxy_command" }

func (p *proxyConn) LocalAddr() net.Addr  { return proxyAddr{} }
func (p *proxyConn) RemoteAddr() net.Addr { return proxyAddr{} }

// SetDeadline closes the connection when t passes, which is what the
// handshake's deadline needs; the zero time clears it. Pipes have no
// deadlines of their own.
func (p *proxyConn) SetDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
	if !t.IsZero() {
		p.timer = time.AfterFunc(time.Until(t), func() { _ = p.Close() })
	}
	return nil
}

func (p *proxyConn) SetReadDeadline(t time.Time) error  { return p.SetDeadline(t) }
func (p *proxyConn) SetWriteDeadline(t time.Time) error { return p.SetDeadline(t) }

// limitedWriter keeps the first n bytes and drops the rest.
type limitedWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
	n  int
}

func (l *limitedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if room := l.n - l.w.Len(); room > 0 {
		if len(b) > room {
			l.w.Write(b[:room])
		} else {
			l.w.Write(b)
		}
	}
	return len(b), nil
}
