// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build !windows

package ssh

import (
	"errors"
	"fmt"
	"net"
)

// dialAgent connects to the SSH agent at sock, SSH_AUTH_SOCK's value.
func dialAgent(sock string) (net.Conn, error) {
	if sock == "" {
		return nil, errors.New("no private_key given and no SSH agent (SSH_AUTH_SOCK is not set)")
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("connecting to the SSH agent: %w", err)
	}
	return conn, nil
}
