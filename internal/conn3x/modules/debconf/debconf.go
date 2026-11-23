// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package debconf presets the answers Debian packages ask for when they
// install, so apt never stops at a prompt.
package debconf

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Types are the question types debconf-set-selections takes.
var Types = []string{"boolean", "error", "multiselect", "note", "password", "select", "string", "text", "title"}

var (
	packageName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
	questionKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./:+-]*$`)
)

// Selection is one answer: the question a package asks, its type and the
// value it should have.
type Selection struct{ Package, Question, Type, Value string }

// Validate checks a Selection before anything reaches the host.
func (s Selection) Validate() error {
	if !packageName.MatchString(s.Package) {
		return fmt.Errorf("name %q is not a Debian package name", s.Package)
	}
	if !questionKey.MatchString(s.Question) {
		return fmt.Errorf("question %q is not a debconf question such as postfix/main_mailer_type", s.Question)
	}
	known := false
	for _, t := range Types {
		known = known || t == s.Type
	}
	if !known {
		return fmt.Errorf("vtype must be one of %s, not %q", strings.Join(Types, ", "), s.Type)
	}
	if strings.ContainsAny(s.Value, "\r\n") {
		return errors.New("value must be a single line")
	}
	// debconf-set-selections records any text for a boolean; the package
	// then reads it as false.
	if s.Type == "boolean" && s.Value != "true" && s.Value != "false" {
		return fmt.Errorf(`a boolean's value must be "true" or "false", not %q`, s.Value)
	}
	return nil
}

// Read returns the answer the host has for s.Question and whether it has
// one. debconf-show prints every other type's answer; a password it hides,
// so that is asked for through debconf-communicate.
func Read(ctx context.Context, r modules.Runner, s Selection) (value string, exists bool, err error) {
	if err := s.Validate(); err != nil {
		return "", false, err
	}
	if s.Type == "password" {
		res, err := run(ctx, r, "DEBIAN_FRONTEND=noninteractive debconf-communicate", []byte("GET "+s.Question+"\n"))
		if err != nil {
			return "", false, err
		}
		code, rest, _ := strings.Cut(strings.TrimSuffix(string(res.Stdout), "\n"), " ")
		switch code {
		case "0":
			return rest, true, nil
		case "10": // the question doesn't exist
			return "", false, nil
		}
		return "", false, fmt.Errorf("debconf-communicate: %s", strings.TrimSpace(string(res.Stderr)+string(res.Stdout)))
	}
	res, err := run(ctx, r, "debconf-show "+ssh.Quote(s.Package), nil)
	if err := check(res, err); err != nil {
		return "", false, err
	}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		// "* question: value", with the * when the question has been seen.
		if v, ok := strings.CutPrefix(strings.TrimLeft(line, "* "), s.Question+":"); ok {
			return strings.TrimPrefix(v, " "), true, nil
		}
	}
	return "", false, nil
}

// Apply records s with debconf-set-selections and reads it back, since the
// tool exits 0 on a line it skipped.
func Apply(ctx context.Context, r modules.Runner, s Selection) error {
	if err := s.Validate(); err != nil {
		return err
	}
	family, err := pkg.DetectFamily(ctx, r)
	if err != nil {
		return err
	}
	if family != pkg.Deb {
		return errors.New("debconf presets the questions Debian and Ubuntu packages ask; this host isn't Debian or Ubuntu, so it has no debconf: drop the step for it")
	}
	line := strings.Join([]string{s.Package, s.Question, s.Type, s.Value}, " ")
	res, err := run(ctx, r, "DEBIAN_FRONTEND=noninteractive debconf-set-selections", []byte(line+"\n"))
	if err := check(res, err); err != nil {
		return err
	}
	got, ok, err := Read(ctx, r, s)
	if err != nil {
		return err
	}
	if !ok || got != s.Value {
		if s.Type == "password" {
			got = "(another password)" // never put a secret in an error
		}
		return fmt.Errorf("debconf kept %q for %s after setting it; debconf-set-selections said: %s", got, s.Question, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// lockedMessage is how debconf says another process has its database open,
// as apt and dpkg do while they configure a package. It doesn't wait.
const lockedMessage = "is locked by another process"

// lockWait and lockPoll bound how long run waits out that lock, as pkg.Run
// does apt's.
var lockWait, lockPoll = 5 * time.Minute, 2 * time.Second

// run runs a debconf command, trying again while its database is locked.
func run(ctx context.Context, r modules.Runner, cmd string, stdin []byte) (ssh.Result, error) {
	deadline := time.Now().Add(lockWait)
	for {
		res, err := r.Run(ctx, cmd, stdin)
		if err != nil || res.ExitCode == 0 || !strings.Contains(string(res.Stderr)+string(res.Stdout), lockedMessage) || time.Now().After(deadline) {
			return res, err
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(lockPoll):
		}
	}
}

func check(res ssh.Result, err error) error {
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return errors.New(strings.TrimSpace(string(res.Stderr) + string(res.Stdout)))
	}
	return nil
}
