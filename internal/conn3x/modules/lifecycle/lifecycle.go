// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package lifecycle reboots hosts and waits for things to be ready on them.
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// DefaultWait is how long WaitFor waits when no timeout is given.
const DefaultWait = 5 * time.Minute

// WaitFor waits until a path exists or a TCP port is listening on the host.
type WaitFor struct {
	Path    string
	Port    int
	Timeout time.Duration
}

// Validate checks a WaitFor before anything reaches the host.
func (w WaitFor) Validate() error {
	switch {
	case (w.Path == "") == (w.Port == 0):
		return errors.New("set exactly one of path or port")
	case w.Path != "" && (!path.IsAbs(w.Path) || strings.ContainsAny(w.Path, "\r\n")):
		return fmt.Errorf("path %q must be an absolute path", w.Path)
	case w.Path == "" && (w.Port < 1 || w.Port > 65535):
		return fmt.Errorf("port %d is out of range 1 to 65535", w.Port)
	}
	return nil
}

// condition is a shell test that succeeds once the wait is over. Ports are
// read from /proc/net, which every Linux host has, with or without ss.
func (w WaitFor) condition() string {
	if w.Path != "" {
		return "test -e " + ssh.Quote(w.Path)
	}
	return fmt.Sprintf(`awk -v p=%04X 'FNR > 1 && $4 == "0A" { split($2, a, ":"); if (a[2] == p) found = 1 } END { exit !found }' /proc/net/tcp /proc/net/tcp6 2>/dev/null`, w.Port)
}

func (w WaitFor) String() string {
	if w.Path != "" {
		return w.Path
	}
	return fmt.Sprintf("port %d", w.Port)
}

// Ready reports whether the wait is already over.
func (w WaitFor) Ready(ctx context.Context, r modules.Runner) (bool, error) {
	res, err := r.Run(ctx, w.condition(), nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// Wait polls on the host once a second until the wait is over or times out.
func (w WaitFor) Wait(ctx context.Context, r modules.Runner) error {
	if err := w.Validate(); err != nil {
		return err
	}
	timeout := w.Timeout
	if timeout <= 0 {
		timeout = DefaultWait
	}
	secs := int(timeout.Round(time.Second) / time.Second)
	script := fmt.Sprintf(`i=0
until %s; do
  i=$((i + 1))
  if [ "$i" -ge %d ]; then echo "timed out after %s waiting for %s" >&2; exit 1; fi
  sleep 1
done`, w.condition(), secs, timeout.Round(time.Second), w)
	res, err := r.Run(ctx, script, nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return errors.New(strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// BootID identifies the host's current boot; it changes on every reboot.
func BootID(ctx context.Context, r modules.Runner) (string, error) {
	res, err := r.Run(ctx, "cat /proc/sys/kernel/random/boot_id", nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("reading the boot id: %s", strings.TrimSpace(string(res.Stderr)))
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}

// ScheduleReboot starts a reboot two seconds from now, detached, so the
// command returns before the connection drops.
func ScheduleReboot(ctx context.Context, r modules.Runner) error {
	res, err := r.Run(ctx, `nohup sh -c 'sleep 2; systemctl reboot || reboot' >/dev/null 2>&1 &`, nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("scheduling a reboot: %s", strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}
