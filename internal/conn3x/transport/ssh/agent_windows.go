// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
)

// windowsAgentPipe is where the OpenSSH agent that ships with Windows
// listens. SSH_AUTH_SOCK is usually unset there.
const windowsAgentPipe = `\\.\pipe\openssh-ssh-agent`

// dialAgent connects to the SSH agent at sock, SSH_AUTH_SOCK's value: a
// named pipe, or a Unix socket such as one Git Bash or WSL interop sets.
// Unset means Windows' own agent.
func dialAgent(sock string) (net.Conn, error) {
	if sock == "" {
		sock = windowsAgentPipe
	}
	var conn net.Conn
	var err error
	if strings.HasPrefix(sock, `\\.\pipe\`) {
		timeout := 5 * time.Second
		conn, err = winio.DialPipe(sock, &timeout)
	} else {
		conn, err = net.Dial("unix", sock)
	}
	if err != nil {
		if sock == windowsAgentPipe {
			return nil, fmt.Errorf("no private_key given, and the Windows SSH agent isn't answering at %s (start it with \"Start-Service ssh-agent\" and add your key with ssh-add): %w", sock, err)
		}
		return nil, fmt.Errorf("connecting to the SSH agent at %s: %w", sock, err)
	}
	return conn, nil
}
