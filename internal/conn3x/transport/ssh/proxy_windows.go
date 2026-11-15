// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build windows

package ssh

import (
	"os/exec"
	"strconv"
)

func ownGroup(*exec.Cmd) {}

// killTree ends the proxy and the processes it started, such as aws's
// session-manager-plugin. Windows has no process groups to signal.
func killTree(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
	_ = cmd.Process.Kill()
}
