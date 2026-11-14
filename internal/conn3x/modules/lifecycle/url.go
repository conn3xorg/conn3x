// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package lifecycle

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
)

// RemoteDialer opens a TCP connection from the host, as an SSH client's
// direct-tcpip channel does.
type RemoteDialer interface {
	DialRemote(ctx context.Context, addr string) (net.Conn, error)
}

// URLCheck is an HTTP or HTTPS request made from the host, through the SSH
// connection, so it reaches what the host reaches and needs no curl there.
type URLCheck struct {
	URL           string
	StatusCodes   []int  // the answers that count; 200 when empty
	BodyContains  string // text the body must hold, if set
	SkipTLSVerify bool
}

// bodyLimit is how much of a body URLCheck reads to look for BodyContains.
const bodyLimit = 1 << 20

// Validate checks a URLCheck before anything reaches the host.
func (u URLCheck) Validate() error {
	p, err := url.Parse(u.URL)
	switch {
	case err != nil:
		return fmt.Errorf("url %q: %w", u.URL, err)
	case p.Scheme != "http" && p.Scheme != "https":
		return fmt.Errorf("url %q must start with http:// or https://", u.URL)
	case p.Host == "":
		return fmt.Errorf("url %q has no host", u.URL)
	case p.User != nil:
		return fmt.Errorf("url %q holds a user or password, which would land in state; put credentials somewhere else", u.URL)
	}
	for _, c := range u.StatusCodes {
		if c < 100 || c > 599 {
			return fmt.Errorf("status code %d is out of range 100 to 599", c)
		}
	}
	return nil
}

func (u URLCheck) codes() []int {
	if len(u.StatusCodes) == 0 {
		return []int{200}
	}
	return u.StatusCodes
}

// check makes the request once. why says what isn't right yet, "" when the
// answer is the one wanted; err is for a runner that can't reach the host's
// network at all.
func (u URLCheck) check(ctx context.Context, r modules.Runner) (why string, err error) {
	d, ok := r.(RemoteDialer)
	if !ok {
		return "", errors.New("url needs the SSH connection to make the request from the host")
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			// Never a proxy from this machine's environment: the request is
			// the host's.
			Proxy:               nil,
			DialContext:         func(ctx context.Context, _, addr string) (net.Conn, error) { return d.DialRemote(ctx, addr) },
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: u.SkipTLSVerify}, //nolint:gosec // only when skip_tls_verify asks
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.URL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		// sshd with AllowTcpForwarding no will never let the request out.
		if strings.Contains(err.Error(), "administratively prohibited") {
			return "", fmt.Errorf("the host's sshd doesn't allow TCP forwarding, which url needs: %w", err)
		}
		return err.Error(), nil
	}
	defer resp.Body.Close()
	if !slices.Contains(u.codes(), resp.StatusCode) {
		return fmt.Sprintf("answered %s, not %s", resp.Status, joinCodes(u.codes())), nil
	}
	if u.BodyContains != "" {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
		if !bytes.Contains(body, []byte(u.BodyContains)) {
			return fmt.Sprintf("answered %s, but the body doesn't hold %q", resp.Status, u.BodyContains), nil
		}
	}
	return "", nil
}

func joinCodes(codes []int) string {
	s := make([]string, len(codes))
	for i, c := range codes {
		s[i] = fmt.Sprint(c)
	}
	return strings.Join(s, " or ")
}

// wait asks once a second until the answer is right or timeout passes, and
// then says what the last answer was.
func (u URLCheck) wait(ctx context.Context, r modules.Runner, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		why, err := u.check(ctx, r)
		if err != nil {
			return err
		}
		if why == "" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for %s: %s", timeout.Round(time.Second), u.URL, why)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
