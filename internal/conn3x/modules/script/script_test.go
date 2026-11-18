// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package script

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/moduletest"
)

// A shell program that echoes its mode's answer, and records each call's
// stdin, so tests see what Conn3x sent.
const echo = `#!/bin/sh
in=$(cat)
printf '%s\n' "$in" >> "$CALLS"
case "$in" in
*'"mode":"read"'*) echo '{"state":{"value":"old"}}' ;;
*'"mode":"plan"'*) echo '{"in_sync":false,"changes":[{"path":"value","before":"old","after":"new"}]}' ;;
*'"mode":"apply"'*) echo '{"state":{"value":"new"},"changed":true}' ;;
*'"mode":"remove"'*) echo '{}' ;;
esac
`

func setup(t *testing.T) (context.Context, string) {
	t.Helper()
	dir := t.TempDir()
	saved := Dir
	Dir = filepath.Join(dir, "modules")
	t.Cleanup(func() { Dir = saved })
	calls := filepath.Join(dir, "calls")
	t.Setenv("CALLS", calls)
	return context.Background(), calls
}

func TestCallModes(t *testing.T) {
	ctx, calls := setup(t)
	s := Script{Program: []byte(echo), Interpreter: []string{"sh"}, Args: json.RawMessage(`{"value":"new"}`), ArgsWO: json.RawMessage(`{"secret":"s3"}`)}
	r := moduletest.Local{}

	got, err := s.Call(ctx, r, "read", nil)
	if err != nil || string(got.State) != `{"value":"old"}` {
		t.Fatalf("read: %s, %v", got.State, err)
	}
	plan, err := s.Call(ctx, r, "plan", got.State)
	if err != nil || plan.InSync == nil || *plan.InSync || !strings.Contains(string(plan.Changes), `"after":"new"`) {
		t.Fatalf("plan: %+v, %v", plan, err)
	}
	applied, err := s.Call(ctx, r, "apply", got.State)
	if err != nil || !applied.Changed || string(applied.State) != `{"value":"new"}` {
		t.Fatalf("apply: %+v, %v", applied, err)
	}
	if _, err := s.Call(ctx, r, "remove", applied.State); err != nil {
		t.Fatal(err)
	}

	// The program went to Dir under its hash, 0700; args_wo reached apply
	// and nothing else.
	fi, err := os.Stat(filepath.Join(Dir, s.Sum()))
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("program on host: %v %v", fi, err)
	}
	b, _ := os.ReadFile(calls)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 4 {
		t.Fatalf("%d calls", len(lines))
	}
	for i, l := range lines {
		if strings.Contains(l, "s3") != (i == 2) {
			t.Errorf("call %d: args_wo present = %v: %s", i, strings.Contains(l, "s3"), l)
		}
	}
	if !strings.Contains(lines[1], `"state":{"value":"old"}`) {
		t.Errorf("plan didn't get read's state: %s", lines[1])
	}
}

func TestCallErrors(t *testing.T) {
	ctx, _ := setup(t)
	r := moduletest.Local{}
	for name, tc := range map[string]struct{ program, want string }{
		"error field":   {`echo '{"error":"no such site"}'`, "no such site"},
		"non-zero exit": {`echo oops >&2; exit 3`, "exited 3: oops"},
		"not JSON":      {`echo hello`, "didn't print JSON"},
		"plan, no sync": {`echo '{"changes":[]}'`, `no "in_sync"`},
	} {
		s := Script{Program: []byte("cat >/dev/null\n" + tc.program + "\n"), Interpreter: []string{"sh"}}
		mode := "read"
		if name == "plan, no sync" {
			mode = "plan"
		}
		if _, err := s.Call(ctx, r, mode, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestValidate(t *testing.T) {
	for _, s := range []Script{
		{},
		{Program: make([]byte, MaxProgram+1)},
		{Program: []byte("x"), Args: json.RawMessage("{nope")},
	} {
		if s.Validate() == nil {
			t.Errorf("%d-byte program with args %q validated", len(s.Program), s.Args)
		}
	}
	if err := (Script{Program: []byte("x"), Args: json.RawMessage(`{"a":1}`)}).Validate(); err != nil {
		t.Error(err)
	}
}

// A program that hands an args_wo value back, in state or in changes, is
// refused, so Conn3x never stores it.
func TestCallRefusesArgsWOInOutput(t *testing.T) {
	ctx, _ := setup(t)
	r := moduletest.Local{}
	for name, out := range map[string]string{
		"state":   `{"state":{"conf":{"password":"hunter2"}},"changed":true}`,
		"changes": `{"in_sync":false,"changes":[{"path":"password","after":"hunter2"}]}`,
	} {
		s := Script{Program: []byte("cat >/dev/null\necho '" + out + "'\n"), Interpreter: []string{"sh"}, ArgsWO: json.RawMessage(`{"password":"hunter2"}`)}
		if _, err := s.Call(ctx, r, "apply", nil); err == nil || !strings.Contains(err.Error(), "args_wo value") {
			t.Errorf("%s: %v", name, err)
		}
	}
	ok := Script{Program: []byte("cat >/dev/null\necho '{\"state\":{\"user\":\"app\"}}'\n"), Interpreter: []string{"sh"}, ArgsWO: json.RawMessage(`{"password":"hunter2"}`)}
	if _, err := ok.Call(ctx, r, "apply", nil); err != nil {
		t.Errorf("state without the secret: %v", err)
	}
}
