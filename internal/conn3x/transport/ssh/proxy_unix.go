// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build !windows

package ssh

import (
	"os/exec"
	"syscall"
)

// ownGroup puts the proxy in a process group of its own, so killing it
// takes the children it starts too, such as aws's session-manager-plugin.
func ownGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killTree(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
