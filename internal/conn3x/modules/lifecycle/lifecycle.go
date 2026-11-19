// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package lifecycle reboots hosts and waits for things to be ready on them.
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// DefaultWait is how long WaitFor waits when no timeout is given.
const DefaultWait = 5 * time.Minute

// WaitFor waits until a path exists, a TCP port is listening, or a URL
// answers on the host.
type WaitFor struct {
	Path string
	// Contains, with Path, is a regular expression the file must match,
	// with ^ and $ at each line as Ansible's search_regex has them.
	Contains string
	Port     int
	URL      URLCheck
	Timeout  time.Duration
}

// tailBytes is how much of the end of a file Contains is matched against.
const tailBytes = 1 << 20

// Validate checks a WaitFor before anything reaches the host.
func (w WaitFor) Validate() error {
	set := 0
	for _, on := range []bool{w.Path != "", w.Port != 0, w.URL.URL != ""} {
		if on {
			set++
		}
	}
	// Before the switch, so no case that returns early, such as contains,
	// can let a relative path through.
	if w.Path != "" && (!path.IsAbs(w.Path) || strings.ContainsAny(w.Path, "\r\n")) {
		return fmt.Errorf("path %q must be an absolute path", w.Path)
	}
	switch {
	case set != 1:
		return errors.New("set exactly one of path, port or url")
	case w.Contains != "" && w.Path == "":
		return errors.New("contains is for path, not port or url; for url, use body_contains")
	case w.Contains != "":
		if _, err := regexp.Compile(w.Contains); err != nil {
			return fmt.Errorf("contains isn't a regular expression: %w", err)
		}
	case w.URL.URL != "":
		return w.URL.Validate()
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
	if w.URL.URL != "" {
		return w.URL.URL
	}
	if w.Path != "" {
		return w.Path
	}
	return fmt.Sprintf("port %d", w.Port)
}

// Ready reports whether the wait is already over.
func (w WaitFor) Ready(ctx context.Context, r modules.Runner) (bool, error) {
	if w.URL.URL != "" {
		why, err := w.URL.check(ctx, r)
		return err == nil && why == "", err
	}
	if w.Contains != "" {
		return w.matches(ctx, r)
	}
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
	if w.URL.URL != "" {
		return w.URL.wait(ctx, r, timeout)
	}
	if w.Contains != "" {
		return w.waitContains(ctx, r, timeout)
	}
	secs := int(timeout.Round(time.Second) / time.Second)
	script := fmt.Sprintf(`i=0
until %s; do
  i=$((i + 1))
  if [ "$i" -ge %d ]; then echo %s >&2; exit 1; fi
  sleep 1
done`, w.condition(), secs, ssh.Quote(fmt.Sprintf("timed out after %s waiting for %s", timeout.Round(time.Second), w)))
	res, err := r.Run(ctx, script, nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return errors.New(strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// matches reports whether the last MiB of the file matches Contains. A
// file that isn't there yet doesn't.
func (w WaitFor) matches(ctx context.Context, r modules.Runner) (bool, error) {
	res, err := r.Run(ctx, fmt.Sprintf("test -f %s || exit 3; tail -c %d -- %s", ssh.Quote(w.Path), tailBytes, ssh.Quote(w.Path)), nil)
	if err != nil {
		return false, err
	}
	switch res.ExitCode {
	case 0:
		return regexp.MustCompile("(?m)" + w.Contains).Match(res.Stdout), nil
	case 3:
		return false, nil
	}
	return false, fmt.Errorf("reading %s: %s", w.Path, strings.TrimSpace(string(res.Stderr)))
}

// waitContains reads the file once a second until it matches or times out.
func (w WaitFor) waitContains(ctx context.Context, r modules.Runner, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		ok, err := w.matches(ctx, r)
		if err != nil || ok {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for %s to match %q", timeout.Round(time.Second), w.Path, w.Contains)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
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
