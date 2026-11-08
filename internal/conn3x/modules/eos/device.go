// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package eos configures Arista EOS switches over their own CLI, through SSH.
// There is no shell and no sudo: every command is an EOS CLI command, run on
// its own SSH exec channel, and every change goes through a named config
// session that is committed with a revert timer and confirmed over a new
// connection, so a change that cuts Conn3x off undoes itself. The steps
// for one switch share one session per apply, committed once.
package eos

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	return sessionPrefix + hex.EncodeToString(b)
}

// sessionPrefix starts the name of every session Conn3x opens.
const sessionPrefix = "conn3x-"

// timerText writes a duration the way commit timer takes it, hh:mm:ss.
func timerText(d time.Duration) string {
	s := int(d.Seconds())
	return fmt.Sprintf("%02d:%02d:%02d", s/3600, s/60%60, s%60)
}

// Session is one named config session. Steps add lines to it one after
// another, and nothing is live until Commit: so a switch pays for one
// commit, one wait and one confirm per apply, however many steps changed.
//
// EOS commits a session by replacing running-config with the session's
// copy, which was taken when the session started. A change made to the
// switch in between, by hand or by anything else, would be undone, so
// Commit first checks that running-config is still what the session
// started from.
type Session struct {
	Name    string
	started bool     // the switch has the session: lines went in
	base    [32]byte // running-config when it was read for the first lines
}

// sessionsJSON is show configuration sessions | json, as cEOS-lab 4.37.0F
// prints it.
type sessionsJSON struct {
	Sessions map[string]struct {
		State string `json:"state"`
	} `json:"sessions"`
	CommitTimerSessionName string  `json:"commitTimerSessionName"`
	CommitTimerExpireTime  float64 `json:"commitTimerExpireTime"`
}

// Open starts a session for lines computed from running, the running-config
// just read. It refuses while any session waits on its commit timer, since
// running-config then holds a change that may yet roll back, and a commit
// would be refused anyway. It aborts the pending sessions a Conn3x run left
// when it stopped before committing: they were never live, and EOS keeps
// only five pending sessions. A second run still adding lines to the same
// switch would lose its session that way, and its commit then fails, with
// nothing of it live: two runs at one switch would undo each other anyway.
func Open(ctx context.Context, d Device, running string) (*Session, error) {
	var st sessionsJSON
	if err := ShowJSON(ctx, d, "show configuration sessions", &st); err != nil {
		return nil, err
	}
	if st.CommitTimerSessionName != "" {
		left := time.Until(time.Unix(int64(st.CommitTimerExpireTime), 0)).Round(time.Second)
		return nil, fmt.Errorf("config session %s is waiting to be confirmed, and rolls back in %s unless something confirms it. Nothing was changed. An apply that stopped while waiting leaves this; apply again once it has rolled back", st.CommitTimerSessionName, max(left, 0))
	}
	for name, s := range st.Sessions {
		if strings.HasPrefix(name, sessionPrefix) && s.State == "pending" {
			if _, err := run(ctx, d, "configure session "+name+" abort", nil); err != nil {
				return nil, fmt.Errorf("aborting config session %s, left by an earlier run: %w", name, err)
			}
		}
	}
	return &Session{Name: sessionName(), base: configHash(running)}, nil
}

// configHash hashes a config without its comment lines, such as the
// "! Command:" header, which change between reads.
func configHash(config string) [32]byte {
	var b strings.Builder
	for _, line := range strings.Split(config, "\n") {
		if !strings.HasPrefix(line, "!") {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return sha256.Sum256([]byte(b.String()))
}

// Config is the session's copy of the config, with every line added so
// far: what the next step compares its lines with.
func (s *Session) Config(ctx context.Context, d Device) (string, error) {
	return Show(ctx, d, "show session-config named "+s.Name)
}

// Add puts cmds into the session. It isn't live yet. When the switch
// refuses a line, the caller aborts the session.
func (s *Session) Add(ctx context.Context, d Device, cmds []string) error {
	if len(cmds) == 0 {
		return nil
	}
	// The CLI reads the script from stdin; "end" leaves the session pending.
	script := "configure session " + s.Name + "\n" + strings.Join(cmds, "\n") + "\nend\n"
	s.started = true
	_, err := run(ctx, d, "", []byte(script))
	return err
}

// Abort drops the session and every line in it. Nothing was live.
func (s *Session) Abort(ctx context.Context, d Device) error {
	if !s.started {
		return nil
	}
	if _, err := run(ctx, d, "configure session "+s.Name+" abort", nil); err != nil {
		return fmt.Errorf("aborting config session %s failed, so remove it by hand with \"configure session %s abort\": %w", s.Name, s.Name, err)
	}
	return nil
}

// aborted is err after an abort of s, saying whether the abort worked.
func (s *Session) aborted(ctx context.Context, d Device, err error) error {
	if abortErr := s.Abort(ctx, d); abortErr != nil {
		return fmt.Errorf("%w; %v", err, abortErr)
	}
	return fmt.Errorf("%w. Nothing was changed", err)
}

// Commit makes the session live, all or nothing:
//
//  1. Running-config must still be what the session started from, or the
//     commit would undo whatever changed it; if not, the session is
//     aborted and nothing changes.
//  2. The session is committed with a revert timer of RevertAfter.
//  3. After confirmAfter, a new SSH connection, from reconnect, commits it
//     again, which confirms it. That it can log in at all is the check: if
//     the change cut Conn3x off, the confirm never arrives and EOS rolls
//     the change back by itself. The wait gives the change time to bite.
//  4. The running config is copied to startup-config.
//
// It returns the session's diff as the switch printed it.
func (s *Session) Commit(ctx context.Context, d Device, reconnect func(context.Context) (Device, error), confirmAfter time.Duration) (string, error) {
	if !s.started {
		return "", nil
	}
	session := "configure session " + s.Name
	running, err := RunningConfig(ctx, d)
	if err != nil {
		return "", s.aborted(ctx, d, err)
	}
	if configHash(running) != s.base {
		return "", s.aborted(ctx, d, errors.New("running-config changed while this apply was adding lines to its config session (a change by hand, or another tool or run), and committing the session would undo that change"))
	}
	diff, err := Show(ctx, d, "show session-config named "+s.Name+" diffs")
	if err != nil {
		return "", s.aborted(ctx, d, err)
	}
	if _, err := run(ctx, d, session+" commit timer "+timerText(RevertAfter), nil); err != nil {
		return diff, s.aborted(ctx, d, err)
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

// Apply makes one change in a session of its own: Open, Add and Commit.
// running is the running-config cmds were computed from.
func Apply(ctx context.Context, d Device, reconnect func(context.Context) (Device, error), running string, cmds []string, confirmAfter time.Duration) (string, error) {
	if len(cmds) == 0 {
		return "", nil
	}
	s, err := Open(ctx, d, running)
	if err != nil {
		return "", err
	}
	if err := s.Add(ctx, d, cmds); err != nil {
		return "", s.aborted(ctx, d, err)
	}
	return s.Commit(ctx, d, reconnect, confirmAfter)
}
