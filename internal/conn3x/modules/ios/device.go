// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package ios configures Cisco IOS XE devices over their own CLI, through
// SSH. A show command runs alone on an exec channel; a change is a CLI
// script fed on stdin through a shell request, since configure terminal on
// an exec channel ends with the channel.
//
// IOS has no candidate configuration: each line is live once typed, and a
// line it refuses doesn't stop the ones after it. So a change goes in under
// configure terminal revert timer, which archives the configuration first
// and rolls back to it unless configure confirm arrives. Any refusal reverts
// at once; otherwise Conn3x waits, confirms over a new login, so a change
// that cuts it off rolls back by itself, and saves with write memory.
// Tested on IOS XE 17.18 (IOL-XE) and IOS 15.9 (IOSv) in CML; see #779.
package ios

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Device runs one command per exec channel, and a CLI script on stdin
// through a shell request. An *ssh.Client logged in at privilege 15 is one.
type Device interface {
	RunRaw(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error)
	RunShell(ctx context.Context, stdin []byte) (ssh.Result, error)
}

// PerCommand is a Device that dials for every command and closes the
// connection after it: IOS XE ends the connection when a session ends, so
// a second session on the same one fails.
func PerCommand(dial func(context.Context) (Device, error)) Device { return perCommand(dial) }

type perCommand func(context.Context) (Device, error)

func (dial perCommand) RunRaw(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	d, err := dial(ctx)
	if err != nil {
		return ssh.Result{}, err
	}
	defer closeDevice(d)
	return d.RunRaw(ctx, cmd, stdin)
}

func (dial perCommand) RunShell(ctx context.Context, stdin []byte) (ssh.Result, error) {
	d, err := dial(ctx)
	if err != nil {
		return ssh.Result{}, err
	}
	defer closeDevice(d)
	return d.RunShell(ctx, stdin)
}

func closeDevice(d Device) {
	if c, ok := d.(interface{ Close() error }); ok {
		_ = c.Close()
	}
}

// commandTimeout bounds one command or script.
const commandTimeout = 2 * time.Minute

// RevertAfter is the revert timer: unconfirmed for this long, IOS rolls the
// change back to the archived configuration. It counts in whole minutes.
const RevertAfter = 5 * time.Minute

// The wait between a change and its confirm, as on Junos.
const (
	DefaultConfirmAfter = 30 * time.Second
	MinConfirmAfter     = 5 * time.Second
	MaxConfirmAfter     = RevertAfter - time.Minute // exclusive
)

// CheckConfirmAfter refuses a wait too short to let a change bite, or too
// long for the confirm to beat the rollback.
func CheckConfirmAfter(d time.Duration) error {
	if d < MinConfirmAfter || d >= MaxConfirmAfter {
		return fmt.Errorf("confirm_after must be at least %s and under %s, so a change has time to take effect and the confirm still lands before the %s rollback; got %s", MinConfirmAfter, MaxConfirmAfter, RevertAfter, d)
	}
	return nil
}

// cliError matches a line IOS prints when it refuses something: "% Invalid
// input detected at '^' marker.", "%Rollback Confirmed Change is already
// activated on a config". IOS goes on with the next line regardless.
var cliError = regexp.MustCompile(`(?m)^\s*%\s*(.+)$`)

// notErrors are % lines that report rather than refuse.
var notErrors = []string{"No Rollback Confirmed Change pending"}

func cliErrors(out string) []string {
	var errs []string
	for _, m := range cliError.FindAllStringSubmatch(out, -1) {
		msg := strings.TrimSpace(m[1])
		if !containsAny(msg, notErrors) {
			errs = append(errs, msg)
		}
	}
	return errs
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func run(ctx context.Context, d Device, cmd string, stdin []byte) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	var res ssh.Result
	var err error
	if cmd == "" {
		res, err = d.RunShell(ctx, stdin)
	} else {
		res, err = d.RunRaw(ctx, cmd, stdin)
	}
	if err != nil {
		return "", err
	}
	return string(res.Stdout) + string(res.Stderr), nil
}

// script is a shell session: unpaged, the lines, then exit. Nothing else
// is typed at the exec prompt: IOS takes an unknown word there for a host
// to connect to, so Check makes sure configure terminal will be taken
// before a configuration line is sent.
func script(lines ...string) []byte {
	return []byte("terminal length 0\n" + strings.Join(lines, "\n") + "\nexit\n")
}

// Show runs one command on an exec channel and returns its text. A refusal
// is an error.
func Show(ctx context.Context, d Device, cmd string) (string, error) {
	out, err := run(ctx, d, cmd, nil)
	if err != nil {
		return "", err
	}
	if errs := cliErrors(out); errs != nil {
		return "", fmt.Errorf("the device refused %q: %s", cmd, strings.Join(errs, "; "))
	}
	return out, nil
}

// RunningConfig is show running-config, from its first line after the
// "Current configuration" header to its closing "end". It may hold secrets,
// hashed or not: callers keep only the lines they own, never the whole text.
func RunningConfig(ctx context.Context, d Device) (string, error) {
	out, err := Show(ctx, d, "show running-config")
	if err != nil {
		return "", err
	}
	_, body, ok := strings.Cut(out, "Current configuration")
	if !ok {
		return "", errors.New("show running-config: no \"Current configuration\" header; is this Cisco IOS?")
	}
	_, body, _ = strings.Cut(body, "\n")
	var lines []string
	for _, l := range strings.Split(strings.ReplaceAll(body, "\r", ""), "\n") {
		if strings.TrimSpace(l) == "end" && !strings.HasPrefix(l, " ") {
			break
		}
		lines = append(lines, l)
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// configHash ignores "!" lines: IOS rewrites "! Last configuration change"
// and "! NVRAM config last updated" stamps that aren't configuration.
func configHash(config string) [32]byte {
	var b strings.Builder
	for _, l := range strings.Split(config, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "!") {
			b.WriteString(l + "\n")
		}
	}
	return sha256.Sum256([]byte(b.String()))
}

const noneWaiting = "No Rollback Confirmed Change pending"

// Pending says how the device shows a change waiting for configure
// confirm, or "" when none is.
func Pending(ctx context.Context, d Device) (string, error) {
	out, err := run(ctx, d, "show archive config rollback timer", nil)
	if err != nil {
		return "", err
	}
	if strings.Contains(out, noneWaiting) {
		return "", nil
	}
	if errs := cliErrors(out); errs != nil {
		return "", fmt.Errorf("the device refused \"show archive config rollback timer\": %s", strings.Join(errs, "; "))
	}
	return strings.Join(strings.Fields(out), " "), nil
}

// PendingError is a change refused while another waits for its confirm.
// configure terminal still works then, and its lines would be rolled back
// with the other change, so Conn3x won't type any.
type PendingError struct{ Says string }

func (e PendingError) Error() string {
	return fmt.Sprintf("a change on this device is waiting for configure confirm (%s); it rolls back on its own when its timer runs out, or confirm or revert it by hand, then apply again", e.Says)
}

// ErrNoArchive is a change refused for want of an archive path: without
// one, IOS can't take the revert timer, and there'd be no way back.
var ErrNoArchive = errors.New(`this device has no configuration archive, which the revert timer needs to roll a change back. Configure one first, as "archive" with "path flash:conn3x" (or "path unix:conn3x" on IOL), and Conn3x will use it`)

// Check refuses a change that couldn't be rolled back: no archive path,
// or a change already waiting for its confirm. IOS has no dry run.
func Check(ctx context.Context, d Device, _ []string) error {
	out, err := run(ctx, d, "show archive", nil)
	if err != nil {
		return NotLiveError{err}
	}
	if !strings.Contains(out, "next archive file will be named") {
		return NotLiveError{ErrNoArchive}
	}
	says, err := Pending(ctx, d)
	if err != nil {
		return NotLiveError{err}
	}
	if says != "" {
		return PendingError{says}
	}
	return nil
}

// NotLiveError is an error that left nothing live on the device.
type NotLiveError struct{ Err error }

func (e NotLiveError) Error() string { return e.Err.Error() + ". Nothing was changed" }
func (e NotLiveError) Unwrap() error { return e.Err }

// session is the configuration script for cmds: each top-level command
// after the first starts from configuration mode again, so a command can't
// land in the block the last one left open.
func session(cmds []string) []string {
	minutes := int(RevertAfter / time.Minute)
	lines := []string{fmt.Sprintf("configure terminal revert timer %d", minutes)}
	for i, c := range cmds {
		if i > 0 && !strings.HasPrefix(c, " ") {
			lines = append(lines, "end", "configure terminal")
		}
		lines = append(lines, c)
	}
	return append(lines, "end")
}

// Apply makes cmds live: under the revert timer, then confirmed over a new
// login after confirmAfter, then saved. base is the configuration cmds were
// worked out from; if the device has moved on, nothing is typed.
func Apply(ctx context.Context, d Device, reconnect func(context.Context) (Device, error), base string, cmds []string, confirmAfter time.Duration) (string, error) {
	if len(cmds) == 0 {
		return "", nil
	}
	diff := strings.Join(cmds, "\n")
	if err := Check(ctx, d, cmds); err != nil {
		return diff, err
	}
	now, err := RunningConfig(ctx, d)
	if err != nil {
		return diff, NotLiveError{err}
	}
	if configHash(now) != configHash(base) {
		return diff, NotLiveError{errors.New("the configuration changed while this apply was working out its lines (a change by hand, or another tool or run), and applying would undo that change")}
	}
	out, err := run(ctx, d, "", script(session(cmds)...))
	if err != nil {
		return diff, fmt.Errorf("the session ended before IOS said whether the lines took (%w). If any did, Conn3x won't confirm them, so they roll back on their own within %s", err, RevertAfter)
	}
	if !strings.Contains(out, "Backing up current running config") {
		return diff, NotLiveError{fmt.Errorf("IOS didn't start the revert timer: %s", lastLines(out, 5))}
	}
	if errs := cliErrors(out); errs != nil {
		why := fmt.Errorf("the device refused the change: %s", strings.Join(errs, "; "))
		back, rerr := run(ctx, d, "", script("configure revert now"))
		if rerr == nil && strings.Contains(back, "Rollback Done") {
			return diff, NotLiveError{why}
		}
		return diff, fmt.Errorf("%w; reverting at once didn't say it was done (%v), so the change rolls back on its own within %s", why, rerr, RevertAfter)
	}
	wait := time.NewTimer(confirmAfter)
	select {
	case <-ctx.Done():
		wait.Stop()
		return diff, fmt.Errorf("stopped before confirming, so the device rolls the change back on its own within %s: %w", RevertAfter, ctx.Err())
	case <-wait.C:
	}
	fresh, err := reconnect(ctx)
	if err == nil {
		out, err = run(ctx, fresh, "", script("configure confirm", "show archive config rollback timer", "write memory"))
		if c, ok := fresh.(interface{ Close() error }); ok {
			_ = c.Close()
		}
		if err == nil && (cliErrors(out) != nil || !strings.Contains(out, noneWaiting)) {
			err = fmt.Errorf("the confirm wasn't taken: %s", lastLines(out, 5))
		}
	}
	if err != nil {
		return diff, fmt.Errorf("applied under a %s revert timer, but couldn't confirm it over a new connection, so the device rolls the change back on its own: %w", RevertAfter, err)
	}
	if !strings.Contains(out, "[OK]") {
		return diff, fmt.Errorf("confirmed, but write memory didn't say [OK], so the change is live but may not survive a reload: %s", lastLines(out, 5))
	}
	return diff, nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
