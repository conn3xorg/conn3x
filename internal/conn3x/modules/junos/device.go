// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package junos configures Juniper Junos devices over their own CLI, through
// SSH. The login is a CLI login, never a shell: operational commands run one
// per exec channel, and a change is a CLI script fed on stdin. Junos exits 0
// whatever a script hit, so every result is read for the CLI's own errors.
//
// A change goes in twice. First in configure private, checked with commit
// check and thrown away: if anything in it is refused, nothing changed.
// Then in configure exclusive with commit confirmed, confirmed after a wait
// over a new connection, so a change that cuts Conn3x off rolls back by
// itself. Junos refuses commit confirmed in private mode, hence the two.
package junos

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Device runs one operational command per exec channel, and a CLI script
// on stdin through a shell request: a command on an exec channel runs alone
// in the Junos CLI, with stdin unread. An *ssh.Client logged in as a CLI
// user is one.
type Device interface {
	RunRaw(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error)
	RunShell(ctx context.Context, stdin []byte) (ssh.Result, error)
}

// commandTimeout bounds one command or script.
const commandTimeout = 2 * time.Minute

// RevertAfter is the commit confirmed timer: unconfirmed for this long, Junos
// rolls the commit back on its own. It counts in whole minutes.
const RevertAfter = 5 * time.Minute

// The wait between commit and confirm, as on EOS: long enough for a change to
// bite, short enough for the confirm to land inside RevertAfter.
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

// secretWord matches a secret-bearing keyword in a statement and the rest of
// the line: encrypted-password "$6$...", authentication-key "$9$...",
// secret, community, pre-shared-key ascii-text. A public key stays readable.
var secretWord = regexp.MustCompile(`(?mi)(^|\s)(encrypted-password|plain-text-password-value|authentication-key|simple-password|secret|community|pre-shared-key|ascii-text|hexadecimal|key)[ \t]+(\S.*)$`)

// Mask hides passwords, keys and their hashes in CLI text before it's logged
// or put in an error.
func Mask(text string) string {
	return secretWord.ReplaceAllString(text, "$1$2 <hidden>")
}

// refusal matches how the CLI says it refused a line or a commit: an error:
// line, a syntax error, or the caret it prints under the word it stopped at.
var refusal = regexp.MustCompile(`(?m)^\s*(error: .*|syntax error.*|unknown command.*|missing argument.*|invalid (?:value|ip address|prefix).*|.*is ambiguous.*)$`)

// xnmError matches an error in | display xml output and its message.
var xnmError = regexp.MustCompile(`(?s)<xnm:error[^>]*>.*?<message>\s*(.*?)\s*</message>.*?</xnm:error>`)

// cliErrors are the CLI's refusals in out, masked, or nil.
func cliErrors(out string) []string {
	var errs []string
	for _, m := range refusal.FindAllStringSubmatch(out, -1) {
		errs = append(errs, Mask(strings.TrimSpace(m[1])))
	}
	for _, m := range xnmError.FindAllStringSubmatch(out, -1) {
		errs = append(errs, Mask(m[1]))
	}
	return errs
}

// ErrShellLogin is what a command reports when the login lands in a shell
// rather than the CLI, as root's does.
var ErrShellLogin = errors.New(`this login starts in a shell, not the Junos CLI, as root's does. Log in as a user of class super-user ("set system login user ops class super-user authentication ssh-ed25519 ..."), whose login starts in the CLI`)

// shellReply matches what csh says to a CLI command.
var shellReply = regexp.MustCompile(`(?m)(Command not found|cli: not found|No match\.)`)

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
	out := string(res.Stdout) + string(res.Stderr)
	if shellReply.MatchString(out) {
		return out, ErrShellLogin
	}
	return out, nil
}

// Show runs one operational command, with its output unpaged, and returns its
// text. A refusal is an error.
func Show(ctx context.Context, d Device, cmd string) (string, error) {
	out, err := run(ctx, d, cmd+" | no-more", nil)
	if err != nil {
		return "", err
	}
	if errs := cliErrors(out); errs != nil {
		return "", fmt.Errorf("the device refused %q: %s", cmd, strings.Join(errs, "; "))
	}
	return out, nil
}

// RunningConfig is show configuration | display set. It may hold secrets, hashed or
// not: callers keep only the lines they own, never the whole text.
func RunningConfig(ctx context.Context, d Device) (string, error) {
	return Show(ctx, d, "show configuration | display set")
}

// Facts are what a circuit can check before it changes a device.
type Facts struct {
	Hostname string
	Model    string
	Version  string
}

// ReadFacts reads show version | display json. Junos puts every value in an
// array of {"data": ...}.
func ReadFacts(ctx context.Context, d Device) (Facts, error) {
	out, err := Show(ctx, d, "show version | display json")
	if err != nil {
		return Facts{}, err
	}
	type datum []struct {
		Data string `json:"data"`
	}
	var v struct {
		Info []struct {
			Hostname datum `json:"host-name"`
			Model    datum `json:"product-model"`
			Version  datum `json:"junos-version"`
		} `json:"software-information"`
	}
	start := max(strings.Index(out, "{"), 0) // the CLI may echo the command first
	if err := json.Unmarshal([]byte(out[start:]), &v); err != nil || len(v.Info) == 0 {
		return Facts{}, fmt.Errorf("show version: the device didn't answer with Junos JSON (%v); is this Junos?", err)
	}
	first := func(d datum) string {
		if len(d) == 0 {
			return ""
		}
		return d[0].Data
	}
	i := v.Info[0]
	return Facts{Hostname: first(i.Hostname), Model: first(i.Model), Version: first(i.Version)}, nil
}

// pendingConfirm matches what configuration mode prints on entry while a
// commit confirmed waits for its confirm. show system commit can't tell:
// its "rollback in" note stays on the entry once confirmed.
var pendingConfirm = regexp.MustCompile(`commit confirmed will be rolled back in \d+ minutes?`)

// Pending reports how the device says a commit confirmed is waiting for its
// confirm, or "" when none is. While one waits, the configuration holds
// lines that may yet roll back, so they can't count as in sync.
func Pending(ctx context.Context, d Device) (string, error) {
	out, err := run(ctx, d, "", script("configure private", "exit"))
	if err != nil {
		return "", err
	}
	return pendingConfirm.FindString(out), nil
}

// PendingError is an apply refused while a commit confirmed waits, most
// likely an earlier apply's whose session ended before its confirm.
type PendingError struct{ Says string }

func (e PendingError) Error() string {
	return fmt.Sprintf("a commit confirmed is waiting for its confirm (the device says %q), most likely an earlier apply's that lost its session, so its lines may yet roll back. Nothing was changed. Apply again once it has rolled back", e.Says)
}

// NotLiveError is a failure that left nothing live: the device's
// configuration is as it was.
type NotLiveError struct{ Err error }

func (e NotLiveError) Error() string { return e.Err.Error() + ". Nothing was changed" }
func (e NotLiveError) Unwrap() error { return e.Err }

func configHash(config string) [32]byte {
	return sha256.Sum256([]byte(strings.Join(SetLines(config), "\n")))
}

func script(lines ...string) []byte { return []byte(strings.Join(lines, "\n") + "\n") }

// Check is Apply's dry run on its own: cmds in configure private, then
// commit check, then rollback and exit. It changes nothing, and fails with
// a NotLiveError naming the device's refusal, or a PendingError while a
// commit confirmed waits.
func Check(ctx context.Context, d Device, cmds []string) error {
	dry := append(append([]string{"configure private"}, cmds...), "commit check", "rollback 0", "exit")
	out, err := run(ctx, d, "", script(dry...))
	if err != nil {
		return NotLiveError{err}
	}
	if errs := cliErrors(out); errs != nil {
		return NotLiveError{fmt.Errorf("the device refused the change: %s", strings.Join(errs, "; "))}
	}
	if says := pendingConfirm.FindString(out); says != "" {
		return PendingError{says}
	}
	if !strings.Contains(out, "configuration check succeeds") {
		return NotLiveError{fmt.Errorf("commit check didn't say the configuration checks out: %s", Mask(lastLines(out, 5)))}
	}
	return nil
}

// Apply makes cmds live, all or nothing:
//
//  1. A dry run: cmds in configure private, then commit check, then rollback
//     and exit. Any refusal stops here, with nothing changed.
//  2. The configuration must still be base, the one cmds were computed
//     from, or committing would undo whatever changed it.
//  3. cmds again, in configure exclusive, with commit confirmed. A refusal
//     now, though the dry run passed, goes unconfirmed and rolls back.
//  4. After confirmAfter, a new connection from reconnect runs commit check
//     in configure exclusive, which confirms. That it can log in at all is
//     the check: if the change cut Conn3x off, Junos rolls it back itself.
//
// It returns the lines it sent, masked, for the log.
func Apply(ctx context.Context, d Device, reconnect func(context.Context) (Device, error), base string, cmds []string, confirmAfter time.Duration) (string, error) {
	if len(cmds) == 0 {
		return "", nil
	}
	diff := Mask(strings.Join(cmds, "\n"))
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
	minutes := int(RevertAfter / time.Minute)
	live := append(append([]string{"configure exclusive"}, cmds...), fmt.Sprintf("commit confirmed %d and-quit", minutes))
	out, err := run(ctx, d, "", script(live...))
	committed := strings.Contains(out, "commit complete")
	switch errs := cliErrors(out); {
	case err != nil:
		// The commit itself may have cut the session, as a lockout does, so
		// a lost session says nothing about whether it committed.
		return diff, fmt.Errorf("the session ended before Junos said whether it committed (%w). If it did, Conn3x won't confirm it, so it rolls back on its own within %s", err, RevertAfter)
	case !committed && errs != nil:
		return diff, NotLiveError{fmt.Errorf("the device refused the change: %s", strings.Join(errs, "; "))}
	case !committed:
		return diff, NotLiveError{fmt.Errorf("the commit didn't complete: %s", Mask(lastLines(out, 5)))}
	case errs != nil:
		return diff, fmt.Errorf("committed with a %s rollback, but the device refused part of it (%s), so Conn3x won't confirm it and it rolls back on its own", RevertAfter, strings.Join(errs, "; "))
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
		out, err = run(ctx, fresh, "", script("configure exclusive", "commit check", "exit"))
		if c, ok := fresh.(interface{ Close() error }); ok {
			_ = c.Close()
		}
		if err == nil && (cliErrors(out) != nil || !strings.Contains(out, "configuration check succeeds")) {
			err = fmt.Errorf("the confirm wasn't taken: %s", Mask(lastLines(out, 5)))
		}
	}
	if err != nil {
		return diff, fmt.Errorf("committed with a %s rollback, but couldn't confirm it over a new connection, so the device rolls the change back on its own: %w", RevertAfter, err)
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
