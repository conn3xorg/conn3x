// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package moduletest has helpers for testing host modules against the
// local shell, which behaves like a host's.
package moduletest

import (
	"bytes"
	"context"
	"errors"
	"os/exec"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Local runs commands with /bin/sh in the C locale, as a host does.
type Local struct{}

func (Local) Run(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	c := exec.CommandContext(ctx, "/bin/sh", "-c", "export LC_ALL=C; "+cmd)
	c.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	err := c.Run()
	res := ssh.Result{Stdout: out.Bytes(), Stderr: errb.Bytes()}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		res.ExitCode = exit.ExitCode()
		return res, nil
	}
	return res, err
}
