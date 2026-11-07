// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package eos configures Arista EOS switches over their own CLI, through SSH.
// There is no shell and no sudo: every command is an EOS CLI command, run on
// its own SSH exec channel, and every change goes through a named config
// session that is committed with a revert timer and confirmed over a new
// connection, so a change that cuts Conn3x off undoes itself.
package eos

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Device runs one EOS CLI command per call, with stdin fed to it. An
// *ssh.Client logged in as a privilege 15 user is one.
type Device interface {
	RunRaw(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error)
}

// commandTimeout bounds one CLI command. RunRaw needs a deadline, and a
// switch that stops answering mid-command must not hang a whole apply.
const commandTimeout = 2 * time.Minute

// RevertAfter is how long a commit waits to be confirmed before EOS rolls it
// back on its own.
const RevertAfter = 5 * time.Minute

// cliError matches how the EOS CLI reports a command it refused: a line
// starting with "% ", such as "% Invalid input" or "% Incomplete command".
var cliError = regexp.MustCompile(`(?m)^% .*$`)

// run sends cmd, with stdin, and returns what it printed. A refused command
// is an error naming the device's own message.
func run(ctx context.Context, d Device, cmd string, stdin []byte) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	res, err := d.RunRaw(ctx, cmd, stdin)
	if err != nil {
		return "", err
	}
	out := string(res.Stdout) + string(res.Stderr)
	if m := cliError.FindAllString(out, -1); len(m) > 0 {
		return out, fmt.Errorf("the switch refused %s: %s", describe(cmd), strings.Join(m, "; "))
	}
	if res.ExitCode != 0 {
		return out, fmt.Errorf("%s exited %d: %s", describe(cmd), res.ExitCode, strings.TrimSpace(out))
	}
	return out, nil
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

// inSession runs lines inside the named config session, creating it if it
// isn't there yet. The session outlives the CLI process: EOS keeps a named
// session pending until it is committed or aborted.
func inSession(ctx context.Context, d Device, name string, lines ...string) (string, error) {
	var script bytes.Buffer
	fmt.Fprintf(&script, "configure session %s\n", name)
	for _, l := range lines {
		script.WriteString(l + "\n")
	}
	script.WriteString("end\n")
	return run(ctx, d, "", script.Bytes())
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
//  3. A new SSH connection, from reconnect, commits it again, which
//     confirms it. That it can log in at all is the check: if the change
//     cut Conn3x off, the confirm never arrives and EOS rolls the change
//     back by itself.
//  4. The running config is copied to startup-config.
//
// It returns the session's diff as the switch printed it.
func Apply(ctx context.Context, d Device, reconnect func(context.Context) (Device, error), cmds []string) (string, error) {
	if len(cmds) == 0 {
		return "", nil
	}
	name := sessionName()
	abort := func(err error) error {
		if _, abortErr := inSession(ctx, d, name, "abort"); abortErr != nil {
			return fmt.Errorf("%w; aborting config session %s also failed, so remove it by hand with \"configure session %s abort\": %v", err, name, name, abortErr)
		}
		return fmt.Errorf("%w. Nothing was changed", err)
	}
	if _, err := inSession(ctx, d, name, cmds...); err != nil {
		return "", abort(err)
	}
	diff, err := Show(ctx, d, "show session-config named "+name+" diffs")
	if err != nil {
		return "", abort(err)
	}
	if _, err := inSession(ctx, d, name, "commit timer "+timerText(RevertAfter)); err != nil {
		return diff, abort(err)
	}
	fresh, err := reconnect(ctx)
	if err == nil {
		_, err = inSession(ctx, fresh, name, "commit")
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
