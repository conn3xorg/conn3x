// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package modules holds the host modules: each one reads the current state
// of something on a host, says whether it differs from what is wanted, and
// changes it.
package modules

import (
	"context"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Runner runs a shell command on a host. *ssh.Client satisfies it.
type Runner interface {
	Run(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error)
}
