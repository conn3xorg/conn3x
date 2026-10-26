// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"
)

// DialWait dials like Dial, but keeps retrying for up to wait while the host
// isn't answering yet, as with a machine that is still booting. Failures
// that waiting can't fix, such as a wrong host key or a rejected login,
// return at once.
func DialWait(ctx context.Context, cfg Config, wait time.Duration) (*Client, error) {
	deadline := time.Now().Add(wait)
	delay := time.Second
	for {
		c, err := Dial(ctx, cfg)
		if err == nil || !retryable(err) {
			return c, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("%w (still not reachable after %s)", err, wait.Round(time.Second))
		}
		if delay > remaining {
			delay = remaining
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		if delay < 5*time.Second {
			delay *= 2
		}
	}
}

// retryable reports whether a dial error could go away on its own.
func retryable(err error) bool {
	if errors.Is(err, ErrHostKey) {
		return false
	}
	// net.DNSError is a net.Error, but a name the resolver says does not
	// exist won't start existing by waiting. Timeouts and SERVFAIL still retry.
	if dnsErr := (*net.DNSError)(nil); errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "handshake failed: EOF") ||
		strings.Contains(msg, "i/o timeout")
}
