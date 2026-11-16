// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package eos

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Enable is a Device for a login that starts unprivileged: every command
// goes to the CLI on stdin after "enable" and, when the switch has an
// enable password, the password on the next line, which is where the CLI
// reads it without a terminal (on cEOS-lab 4.37.0F). With a wrong
// password the CLI takes the lines after it as more tries, so none of them
// run as commands.
type Enable struct {
	Device   Device
	Password []byte // nil when the switch has no enable password
}

// ErrEnableRefused is what a command reports when enable didn't take the
// password.
var ErrEnableRefused = errors.New("the switch refused the enable password from become_password_file")

// RunRaw runs cmd, or the lines in stdin, in privileged mode.
func (e Enable) RunRaw(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	var in bytes.Buffer
	in.WriteString("enable\n")
	if e.Password != nil {
		in.Write(e.Password)
		in.WriteByte('\n')
	}
	if cmd != "" {
		in.WriteString(cmd + "\n")
	} else {
		in.Write(stdin)
	}
	res, err := e.Device.RunRaw(ctx, "", in.Bytes())
	// The password never belongs in what comes back, wherever the CLI
	// might echo it.
	if len(e.Password) > 0 {
		res.Stdout = bytes.ReplaceAll(res.Stdout, e.Password, []byte("<hidden>"))
		res.Stderr = bytes.ReplaceAll(res.Stderr, e.Password, []byte("<hidden>"))
	}
	if err == nil && res.ExitCode != 0 && strings.Count(string(res.Stderr), "Password:") > 1 {
		return res, ErrEnableRefused
	}
	return res, err
}
