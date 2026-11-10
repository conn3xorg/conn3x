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
	return RunWithInput(ctx, r, cmd, "")
}

// RunWithInput is Run with secret on the command's standard input. A
// command line shows in the host's process list while it runs; standard
// input doesn't. The secret is blanked from the output kept and from the
// error, in case the command echoes it.
func RunWithInput(ctx context.Context, r modules.Runner, cmd, secret string) (Output, error) {
	var stdin []byte
	if secret != "" {
		stdin = []byte(secret)
	}
	res, err := r.Run(ctx, cmd, stdin)
	if err != nil {
		return Output{}, err
	}
	out := Output{Stdout: clip(scrub(string(res.Stdout), secret)), Stderr: clip(scrub(string(res.Stderr), secret)), ExitCode: res.ExitCode}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(out.Stderr)
		if msg == "" {
			msg = strings.TrimSpace(out.Stdout)
		}
		if msg == "" {
			return out, fmt.Errorf("command failed with exit status %d", res.ExitCode)
		}
		return out, fmt.Errorf("command failed with exit status %d:\n%s", res.ExitCode, lastLines(msg, failLines))
	}
	return out, nil
}

const blanked = "(sensitive value)"

// scrub blanks secret from s: all of it, and each of its lines on its own,
// since a command given several values may print only one. Lines under six
// characters are left, or a secret with a short line would blank half of
// everything else.
func scrub(s, secret string) string {
	whole := strings.TrimSpace(secret)
	if whole == "" {
		return s
	}
	s = strings.ReplaceAll(s, whole, blanked)
	for _, line := range strings.Split(whole, "\n") {
		if line = strings.TrimSpace(line); len(line) >= 6 {
			s = strings.ReplaceAll(s, line, blanked)
		}
	}
	return s
}

// failLines is how much of a failed command's output its error shows: the
// end, where the reason usually is.
const failLines = 10

func lastLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return fmt.Sprintf("... (%d earlier lines)\n%s", len(lines)-n, strings.Join(lines[len(lines)-n:], "\n"))
}

func clip(s string) string {
	if len(s) <= MaxOutput {
		return s
	}
	return s[:MaxOutput] + truncated
}
