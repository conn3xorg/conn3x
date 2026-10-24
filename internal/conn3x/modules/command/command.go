// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package command runs arbitrary shell commands: the escape hatch for what
// no module covers yet. Guards say when a command has already done its job,
// so it runs only when needed.
package command

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// MaxOutput is how much of stdout and stderr is kept.
const MaxOutput = 4096

const truncated = "\n[output truncated]"

// Guards decide whether the command still needs to run. Any guard that is
// set must hold for the command to count as done.
type Guards struct {
	Creates string // done once this path exists
	Removes string // done once this path is gone
	Unless  string // done while this command succeeds
}

// Any reports whether at least one guard is set.
func (g Guards) Any() bool { return g.Creates != "" || g.Removes != "" || g.Unless != "" }

// Validate checks the guards before anything runs on a host.
func (g Guards) Validate() error {
	for label, p := range map[string]string{"creates": g.Creates, "removes": g.Removes} {
		if p != "" && !path.IsAbs(p) {
			return fmt.Errorf("%s %q must be an absolute path", label, p)
		}
	}
	return nil
}

// Satisfied reports whether every guard holds. With no guards there is
// nothing to check, so it reports false.
func Satisfied(ctx context.Context, r modules.Runner, g Guards) (bool, error) {
	if !g.Any() {
		return false, nil
	}
	var checks []string
	if g.Creates != "" {
		checks = append(checks, "[ -e "+ssh.Quote(g.Creates)+" ]")
	}
	if g.Removes != "" {
		checks = append(checks, "[ ! -e "+ssh.Quote(g.Removes)+" ]")
	}
	if g.Unless != "" {
		checks = append(checks, "( "+g.Unless+" ) >/dev/null 2>&1")
	}
	res, err := r.Run(ctx, strings.Join(checks, " && "), nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// Output is what a command printed and how it exited.
type Output struct {
	Stdout, Stderr string
	ExitCode       int
}

// Run executes the command. A non-zero exit is an error that includes
// what the command printed.
func Run(ctx context.Context, r modules.Runner, cmd string) (Output, error) {
	res, err := r.Run(ctx, cmd, nil)
	if err != nil {
		return Output{}, err
	}
	out := Output{Stdout: clip(string(res.Stdout)), Stderr: clip(string(res.Stderr)), ExitCode: res.ExitCode}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(out.Stderr)
		if msg == "" {
			msg = strings.TrimSpace(out.Stdout)
		}
		return out, fmt.Errorf("command failed with exit status %d: %s", res.ExitCode, msg)
	}
	return out, nil
}

func clip(s string) string {
	if len(s) <= MaxOutput {
		return s
	}
	return s[:MaxOutput] + truncated
}
