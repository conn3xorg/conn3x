// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package modules holds the host modules: each one reads the current state
// of something on a host, says whether it differs from what is wanted, and
// changes it.
package modules

import (
	"context"
	"fmt"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Runner runs a shell command on a host. *ssh.Client satisfies it.
type Runner interface {
	Run(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error)
}

// A Runner may also implement FileReader or UnitReader to answer a read
// without a shell command. Either returns an error wrapping
// errors.ErrUnsupported when it can't answer exactly as the shell would;
// the module then runs its shell command instead. Any other error is the
// answer, and the shell is not tried.

// FileStat is a path as file.Read's shell command sees it.
type FileStat struct {
	Exists  bool   // the path exists, or is a symlink, even a dangling one
	Regular bool   // it is a regular file, following symlinks
	Mode    uint32 // the path's own permission bits, with setuid, setgid and sticky, as stat %a
	Owner   string // the path's own owner and group, by name
	Group   string
	Content []byte // what reading it gives, following symlinks
}

// FileReader reads a file natively.
type FileReader interface {
	ReadFile(ctx context.Context, path string) (FileStat, error)
}

// UnitReader reads a systemd unit's properties natively, as
// "systemctl show -p" prints them (booleans as yes and no).
type UnitReader interface {
	ReadUnit(ctx context.Context, unit string) (map[string]string, error)
}

// AsUser wraps a shell script so it runs as user rather than as whoever is
// connected. The path work below is under the user's own home, which the
// user controls, so doing it as root would let the user redirect it with a
// symlink and have root read or take ownership of a file elsewhere. Running
// as the user instead means the kernel checks the user's own permissions on
// every path, so following a link the user planted grants nothing they
// couldn't already reach, and no root-owned path is ever touched. The whole
// script runs in one drop, so there is no root-then-user window to race.
//
// runuser is in util-linux on every supported distro and runs the command
// directly, so it works even for an account whose shell is nologin; su,
// which goes through the login shell, is only a fallback. When Conn3x is
// already connected as the user, neither is needed or available without
// root, so the script runs as is.
func AsUser(user, script string) string {
	q := ssh.Quote(user)
	inner := ssh.Quote(script)
	return fmt.Sprintf(`if [ "$(id -u)" = "$(id -u -- %[1]s 2>/dev/null)" ]; then
  sh -c %[2]s
elif command -v runuser >/dev/null 2>&1; then
  runuser -u %[1]s -- sh -c %[2]s
else
  su %[1]s -c %[2]s
fi`, q, inner)
}
