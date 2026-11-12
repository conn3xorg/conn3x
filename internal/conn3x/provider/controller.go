// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"sync"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// onController reports whether an ssh block is a step's with
// on = "controller", which runs on the machine Conn3x runs on.
func onController(conn cty.Value) bool {
	v := optional(conn, "controller")
	return !v.IsNull() && v.IsKnown() && v.True()
}

var controller = sync.OnceValue(func() *hostConn {
	return &hostConn{runner: localRunner{}, host: "controller", rootKey: "controller"}
})

// localRunner runs a command with /bin/sh on the machine Conn3x runs on,
// as whoever runs it, in its working directory and with its environment.
type localRunner struct{}

func (localRunner) Run(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	c := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
	var out, errOut bytes.Buffer
	c.Stdin, c.Stdout, c.Stderr = bytes.NewReader(stdin), &out, &errOut
	err := c.Run()
	res := ssh.Result{Stdout: out.Bytes(), Stderr: errOut.Bytes()}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		res.ExitCode = exit.ExitCode()
		return res, nil
	}
	return res, err
}
