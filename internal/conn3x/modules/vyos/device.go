// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package vyos configures VyOS routers over SSH. Operational commands run
// through VyOS's op-mode wrapper, one per exec channel, and a change is a
// vbash script on stdin, the way VyOS's own scripting works. VyOS lets a
// script carry on past a refused line and commit the rest, so every change
// is checked first, then committed with commit-confirm and confirmed over a
// new login, which also saves it: VyOS keeps nothing across a reboot that
// isn't saved.
package vyos

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/setcfg"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Device runs one command per exec channel, with stdin. An *ssh.Client
// logged in as a VyOS user in the vyattacfg group is one.
type Device interface {
	RunRaw(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error)
}

const commandTimeout = 2 * time.Minute

// RevertAfter is the commit-confirm timer, in whole minutes.
const RevertAfter = 5 * time.Minute

// The wait between commit and confirm, as on EOS and Junos.
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

const (
	opWrapper = "/opt/vyatta/bin/vyatta-op-cmd-wrapper "
	// template makes configure, commit and the rest work in a script.
	template = "source /opt/vyatta/etc/functions/script-template"
)

// secretWord matches a secret-bearing keyword and the rest of its line.
var secretWord = regexp.MustCompile(`(?mi)(^|\s)(plaintext-password|encrypted-password|pre-shared-secret|pre-shared-key|secret|password|community|key)[ \t]+(\S.*)$`)

// Mask hides passwords, keys and their hashes before text is logged or put
// in an error.
func Mask(text string) string {
	return secretWord.ReplaceAllString(text, "$1$2 <hidden>")
}

// refusal matches how VyOS says it refused a line or a commit.
var refusal = regexp.MustCompile(`(?m)^.*(Set failed|Delete failed|Commit failed|is not valid|Invalid command|Value validation failed|is not allowed|Configuration path: .* does not exist).*$`)

func cliErrors(out string) []string {
	var errs []string
	for _, m := range refusal.FindAllString(out, -1) {
		errs = append(errs, Mask(strings.TrimSpace(m)))
	}
	return errs
}

func run(ctx context.Context, d Device, cmd string, stdin []byte) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	res, err := d.RunRaw(ctx, cmd, stdin)
	if err != nil {
		return "", err
	}
	return string(res.Stdout) + string(res.Stderr), nil
}

// Show runs one operational command and returns its text.
func Show(ctx context.Context, d Device, cmd string) (string, error) {
	out, err := run(ctx, d, opWrapper+cmd, nil)
	if err != nil {
		return "", err
	}
	if errs := cliErrors(out); errs != nil {
		return "", fmt.Errorf("the router refused %q: %s", cmd, strings.Join(errs, "; "))
	}
	return out, nil
}

// RunningConfig is show configuration commands, with its quotes written the
// way Normalize writes a step's lines, so the two compare. It may hold
// secrets: callers keep only the lines they own.
func RunningConfig(ctx context.Context, d Device) (string, error) {
	out, err := Show(ctx, d, "show configuration commands")
	if err != nil {
		return "", err
	}
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "set ") {
			lines = append(lines, Normalize(l))
		}
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// script runs lines as a vbash script, after the template and configure.
func script(ctx context.Context, d Device, lines ...string) (string, error) {
	return run(ctx, d, "vbash -s", []byte(template+"\nconfigure\n"+strings.Join(lines, "\n")+"\n"))
}

// Pending reports whether a commit-confirm waits for its confirm: VyOS says
// so only through its systemd timer, which any user can ask about.
func Pending(ctx context.Context, d Device) (bool, error) {
	out, err := run(ctx, d, "systemctl is-active commit-confirm.timer", nil)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == "active", nil
}

// RebootsOnRollback reports whether an unconfirmed commit would reboot the
// router, VyOS's default, rather than reload the previous config.
func RebootsOnRollback(config string) bool {
	return !strings.Contains(config, "set system config-management commit-confirm action reload")
}

// ErrPending is an apply refused while a commit-confirm waits.
var ErrPending = errors.New("a commit-confirm is waiting for its confirm on this router, most likely an earlier apply's that lost its session, so its lines may yet roll back. Nothing was changed. Apply again once it has rolled back")

// NotLiveError is a failure that left nothing live.
type NotLiveError struct{ Err error }

func (e NotLiveError) Error() string { return e.Err.Error() + ". Nothing was changed" }
func (e NotLiveError) Unwrap() error { return e.Err }

// Check runs cmds in configure, then throws them away. It changes nothing.
func Check(ctx context.Context, d Device, cmds []string) error {
	out, err := script(ctx, d, append(append([]string{}, cmds...), "compare", "exit discard")...)
	if err != nil {
		return NotLiveError{err}
	}
	if errs := cliErrors(out); errs != nil {
		return NotLiveError{fmt.Errorf("the router refused the change: %s", strings.Join(errs, "; "))}
	}
	return nil
}

func configHash(config string) [32]byte { return sha256.Sum256([]byte(config)) }

// Apply makes cmds live, all or nothing, as junos.Apply does: refuse while
// a commit-confirm waits; Check; refuse if the config changed since base;
// commit-confirm, answering its question; wait confirmAfter; confirm and
// save over a new connection from reconnect. It returns the lines, masked.
func Apply(ctx context.Context, d Device, reconnect func(context.Context) (Device, error), base string, cmds []string, confirmAfter time.Duration) (string, error) {
	if len(cmds) == 0 {
		return "", nil
	}
	diff := Mask(strings.Join(cmds, "\n"))
	if pending, err := Pending(ctx, d); err != nil || pending {
		if err == nil {
			err = ErrPending
		}
		return diff, NotLiveError{err}
	}
	if err := Check(ctx, d, cmds); err != nil {
		return diff, err
	}
	now, err := RunningConfig(ctx, d)
	if err != nil {
		return diff, NotLiveError{err}
	}
	if configHash(now) != configHash(base) {
		return diff, NotLiveError{errors.New("the configuration changed while this apply was working out its lines (a change by hand, or another tool or run), and committing would undo that change")}
	}
	// commit-confirm asks "Proceed ? [Y/n]" and reads the answer from the
	// script: without the y line it reads on forever.
	minutes := int(RevertAfter / time.Minute)
	out, err := script(ctx, d, append(append([]string{}, cmds...), fmt.Sprintf("commit-confirm %d", minutes), "y", "exit")...)
	committed := strings.Contains(out, "Initialized commit-confirm")
	switch errs := cliErrors(out); {
	case err != nil:
		return diff, fmt.Errorf("the session ended before VyOS said whether it committed (%w). If it did, Conn3x won't confirm it, so it rolls back on its own within %s", err, RevertAfter)
	case !committed && errs != nil:
		return diff, NotLiveError{fmt.Errorf("the router refused the change: %s", strings.Join(errs, "; "))}
	case !committed:
		return diff, NotLiveError{fmt.Errorf("the commit didn't start: %s", Mask(lastLines(out, 4)))}
	case errs != nil:
		return diff, fmt.Errorf("committed with a %s rollback, but the router refused part of it (%s), so Conn3x won't confirm it and it rolls back on its own", RevertAfter, strings.Join(errs, "; "))
	}
	wait := time.NewTimer(confirmAfter)
	select {
	case <-ctx.Done():
		wait.Stop()
		return diff, fmt.Errorf("stopped before confirming, so the router rolls the change back on its own within %s: %w", RevertAfter, ctx.Err())
	case <-wait.C:
	}
	fresh, err := reconnect(ctx)
	if err == nil {
		out, err = script(ctx, fresh, "confirm", "save", "exit")
		if c, ok := fresh.(interface{ Close() error }); ok {
			_ = c.Close()
		}
		if err == nil && !strings.Contains(out, "Reload timer stopped") && !strings.Contains(out, "Reboot timer stopped") {
			err = fmt.Errorf("the confirm wasn't taken: %s", Mask(lastLines(out, 4)))
		}
	}
	if err != nil {
		return diff, fmt.Errorf("committed with a %s rollback, but couldn't confirm it over a new connection, so the router rolls the change back on its own: %w", RevertAfter, err)
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

// Facts are what a circuit can check before it changes a router.
type Facts struct{ Hostname, Version string }

var versionLine = regexp.MustCompile(`(?m)^Version:\s+(.+)$`)

// ReadFacts reads show version and the host name.
func ReadFacts(ctx context.Context, d Device) (Facts, error) {
	out, err := Show(ctx, d, "show version")
	if err != nil {
		return Facts{}, err
	}
	m := versionLine.FindStringSubmatch(out)
	if m == nil {
		return Facts{}, errors.New("show version didn't say a version; is this VyOS?")
	}
	config, err := RunningConfig(ctx, d)
	if err != nil {
		return Facts{}, err
	}
	host := strings.TrimPrefix(setcfg.HaveLeaf(setcfg.SetLines(config), "system host-name"), "set system host-name ")
	return Facts{Hostname: host, Version: strings.TrimSpace(m[1])}, nil
}
