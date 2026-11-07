// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package eos configures Arista EOS switches over their own CLI, through SSH.
// There is no shell and no sudo: every command is an EOS CLI command, run on
// its own SSH exec channel, and every change goes through a named config
// session that is committed with a revert timer and confirmed over a new
// connection, so a change that cuts Conn3x off undoes itself.
package eos

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Device runs one EOS CLI command per call, or with an empty command, the
// CLI lines fed on stdin. An *ssh.Client whose login starts in privileged
// mode is one; see ErrNotPrivileged.
type Device interface {
	RunRaw(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error)
}

// commandTimeout bounds one CLI command. RunRaw needs a deadline, and a
// switch that stops answering mid-command must not hang a whole apply.
const commandTimeout = 2 * time.Minute

// RevertAfter is how long a commit waits to be confirmed before EOS rolls it
// back on its own.
const RevertAfter = 5 * time.Minute

// The wait between commit and confirm. A change takes effect a few seconds
// after its commit (on cEOS-lab 4.37.0F, management ssh shutdown took 3 to 6
// seconds), and a confirm sent sooner would keep a change that cuts Conn3x
// off. The confirm must still land well inside RevertAfter.
const (
	DefaultConfirmAfter = 30 * time.Second
	MinConfirmAfter     = 5 * time.Second
	MaxConfirmAfter     = RevertAfter - time.Minute // exclusive
)

// CheckConfirmAfter refuses a wait too short to let a change bite, or too
// long for the confirm to beat the revert timer.
func CheckConfirmAfter(d time.Duration) error {
	if d < MinConfirmAfter || d >= MaxConfirmAfter {
		return fmt.Errorf("confirm_after must be at least %s and under %s, so a change has time to take effect and the confirm still lands before the %s revert timer; got %s", MinConfirmAfter, MaxConfirmAfter, RevertAfter, d)
	}
	return nil
}

// cliError matches how the EOS CLI explains a command it refused: a line
// starting with "% ", such as "% Invalid input at line 2".
var cliError = regexp.MustCompile(`(?m)^% .*$`)

// echo matches the line the CLI prints back before some output, such as
// "> show running-config", when it reads commands rather than a terminal.
var echo = regexp.MustCompile(`(?m)^> .*\n?`)

// ErrNotPrivileged is what a command reports when the login lands in
// unprivileged mode. Conn3x never sends enable: on a switch with an enable
// password, enable would read the next line of the script as the password.
var ErrNotPrivileged = errors.New(`this login isn't privileged. Give the user privilege 15 ("username ops privilege 15 role network-admin") and add "aaa authorization exec default local", so an SSH login starts in privileged mode`)

// run sends cmd, with stdin, and returns what it printed. EOS exits non-zero
// when it refuses any line, and that is an error naming its own message.
func run(ctx context.Context, d Device, cmd string, stdin []byte) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	res, err := d.RunRaw(ctx, cmd, stdin)
	if err != nil {
		return "", err
	}
	out := echo.ReplaceAllString(string(res.Stdout), "")
	if res.ExitCode == 0 {
		return out, nil
	}
	msg := strings.Join(cliError.FindAllString(string(res.Stdout)+string(res.Stderr), -1), "; ")
	if strings.Contains(msg, "privileged mode required") {
		return out, ErrNotPrivileged
	}
	if msg == "" {
		msg = fmt.Sprintf("exit status %d: %s", res.ExitCode, strings.TrimSpace(string(res.Stdout)+string(res.Stderr)))
	}
	return out, fmt.Errorf("the switch refused %s: %s", describe(cmd), msg)
}

func describe(cmd string) string {
	if cmd != "" {
		return fmt.Sprintf("%q", cmd)
	}
	return "the config session"
}

// Show runs a show command and returns its text.
func Show(ctx context.Context, d Device, cmd string) (string, error) {
	return run(ctx, d, cmd, nil)
}

// ShowJSON runs a show command with "| json" and decodes the result into v.
func ShowJSON(ctx context.Context, d Device, cmd string, v any) error {
	out, err := run(ctx, d, cmd+" | json", nil)
	if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(out), v); err != nil {
		return fmt.Errorf("%q: the switch didn't answer with JSON (%w); is this Arista EOS?", cmd, err)
	}
	return nil
}

// RunningConfig returns show running-config. It may hold secrets, hashed or
// not: callers keep only the lines they own, never the whole text.
func RunningConfig(ctx context.Context, d Device) (string, error) {
	return Show(ctx, d, "show running-config")
}

// Facts are what a circuit can check before it changes a switch.
type Facts struct {
	Hostname  string
	Model     string
	Version   string
	Serial    string
	SystemMAC string
}

// ReadFacts reads show version and show hostname.
func ReadFacts(ctx context.Context, d Device) (Facts, error) {
	var v struct {
		ModelName        string `json:"modelName"`
		Version          string `json:"version"`
		SerialNumber     string `json:"serialNumber"`
		SystemMacAddress string `json:"systemMacAddress"`
	}
	if err := ShowJSON(ctx, d, "show version", &v); err != nil {
		return Facts{}, err
	}
	var h struct {
		Hostname string `json:"hostname"`
	}
	if err := ShowJSON(ctx, d, "show hostname", &h); err != nil {
		return Facts{}, err
	}
	return Facts{Hostname: h.Hostname, Model: v.ModelName, Version: v.Version, Serial: v.SerialNumber, SystemMAC: v.SystemMacAddress}, nil
}

// sessionName is a config session's name, new for every apply so two runs
// never share one.
func sessionName() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "conn3x-" + hex.EncodeToString(b)
}

// timerText writes a duration the way commit timer takes it, hh:mm:ss.
func timerText(d time.Duration) string {
	s := int(d.Seconds())
	return fmt.Sprintf("%02d:%02d:%02d", s/3600, s/60%60, s%60)
}

// Apply makes a change in a config session, all or nothing:
//
//  1. The commands go into a new named session, which isn't live yet. If
//     the switch refuses any of them, the session is aborted and nothing
//     has changed.
//  2. The session is committed with a revert timer of RevertAfter.
//  3. After confirmAfter, a new SSH connection, from reconnect, commits it
//     again, which confirms it. That it can log in at all is the check: if
//     the change cut Conn3x off, the confirm never arrives and EOS rolls
//     the change back by itself. The wait gives the change time to bite.
//  4. The running config is copied to startup-config.
//
// It returns the session's diff as the switch printed it.
func Apply(ctx context.Context, d Device, reconnect func(context.Context) (Device, error), cmds []string, confirmAfter time.Duration) (string, error) {
	if len(cmds) == 0 {
		return "", nil
	}
	name := sessionName()
	session := "configure session " + name
	abort := func(err error) error {
		if _, abortErr := run(ctx, d, session+" abort", nil); abortErr != nil {
			return fmt.Errorf("%w; aborting config session %s also failed, so remove it by hand with \"%s abort\": %v", err, name, session, abortErr)
		}
		return fmt.Errorf("%w. Nothing was changed", err)
	}
	// The CLI reads the script from stdin; "end" leaves the session pending.
	script := session + "\n" + strings.Join(cmds, "\n") + "\nend\n"
	if _, err := run(ctx, d, "", []byte(script)); err != nil {
		return "", abort(err)
	}
	diff, err := Show(ctx, d, "show session-config named "+name+" diffs")
	if err != nil {
		return "", abort(err)
	}
	if _, err := run(ctx, d, session+" commit timer "+timerText(RevertAfter), nil); err != nil {
		return diff, abort(err)
	}
	wait := time.NewTimer(confirmAfter)
	select {
	case <-ctx.Done():
		wait.Stop()
		return diff, fmt.Errorf("stopped before confirming, so the switch will roll the change back on its own in %s: %w", RevertAfter, ctx.Err())
	case <-wait.C:
	}
	fresh, err := reconnect(ctx)
	if err == nil {
		_, err = run(ctx, fresh, session+" commit", nil)
		if c, ok := fresh.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	}
	if err != nil {
		return diff, fmt.Errorf("committed with a %s revert timer, but couldn't confirm it over a new connection, so the switch will roll the change back on its own: %w", RevertAfter, err)
	}
	if _, err := run(ctx, d, "copy running-config startup-config", nil); err != nil {
		return diff, fmt.Errorf("the change is live but wasn't saved, so a reload would lose it: %w", err)
	}
	return diff, nil
}
