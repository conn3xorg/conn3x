// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package script runs a module someone wrote themselves: a program in the
// circuit's directory, in any language the host runs, that speaks JSON on
// stdin and stdout. Conn3x copies it to the host once per content hash and
// keeps the connection, become, plan and state; the program only reads
// and changes the host (#539).
//
// Each call is one run, with {"mode": ..., "args": {...}, "state": {...}}
// on stdin:
//
//	read    returns {"state": {...}}, what's on the host now
//	plan    returns {"in_sync": bool, "changes": [...]}; must change nothing
//	apply   returns {"state": {...}, "changed": bool}
//	remove  returns {}
//
// Any mode may return {"error": "..."}; a non-zero exit is an error too.
package script

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Dir is where programs are kept on the host, each under its SHA-256. A
// variable so tests can point it somewhere they can write.
var Dir = "/var/lib/conn3x/modules"

// MaxProgram is the largest program Conn3x copies to a host.
const MaxProgram = 1 << 20

// Script is one step's program and how to run it.
type Script struct {
	Program     []byte
	Interpreter []string // run the program with these first; empty runs it directly
	Args        json.RawMessage
	ArgsWO      json.RawMessage // apply only; never in plan or state
}

// Sum is the program's SHA-256 in hex.
func (s Script) Sum() string {
	h := sha256.Sum256(s.Program)
	return hex.EncodeToString(h[:])
}

func (s Script) path() string { return Dir + "/" + s.Sum() }

// Validate checks what can be checked without the host.
func (s Script) Validate() error {
	switch {
	case len(s.Program) == 0:
		return errors.New("the program is empty")
	case len(s.Program) > MaxProgram:
		return fmt.Errorf("the program is %d bytes; the most Conn3x copies is %d", len(s.Program), MaxProgram)
	}
	for _, a := range [...]json.RawMessage{s.Args, s.ArgsWO} {
		if len(a) > 0 && !json.Valid(a) {
			return errors.New("args must be JSON")
		}
	}
	return nil
}

// ensure copies the program to the host unless a file with its hash is
// already there, root's and 0700, and checks what arrived.
func (s Script) ensure(ctx context.Context, r modules.Runner) error {
	p := ssh.Quote(s.path())
	cmd := fmt.Sprintf(`sum() { { sha256sum "$1" 2>/dev/null || shasum -a 256 "$1"; } | cut -d' ' -f1; }
p=%[1]s; if [ -f "$p" ] && [ "$(sum "$p")" = %[2]s ]; then exit 0; fi
install -d -m 0700 %[3]s && t=$(mktemp %[3]s/.new.XXXXXX) && cat > "$t" && chmod 0700 "$t" &&
[ "$(sum "$t")" = %[2]s ] && mv -f "$t" "$p" || { rm -f "$t"; echo "the program didn't arrive whole" >&2; exit 1; }`,
		p, ssh.Quote(s.Sum()), ssh.Quote(Dir))
	res, err := r.Run(ctx, cmd, s.Program)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("copying the program to %s: %s", Dir, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// Result is what a call returns.
type Result struct {
	State   json.RawMessage `json:"state,omitempty"`
	InSync  *bool           `json:"in_sync,omitempty"`
	Changes json.RawMessage `json:"changes,omitempty"`
	Changed bool            `json:"changed,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// Call runs the program in mode, with state from the last read or apply.
func (s Script) Call(ctx context.Context, r modules.Runner, mode string, state json.RawMessage) (Result, error) {
	if err := s.ensure(ctx, r); err != nil {
		return Result{}, err
	}
	in := map[string]any{"mode": mode, "args": orEmpty(s.Args), "state": orEmpty(state)}
	if mode == "apply" && len(s.ArgsWO) > 0 {
		in["args_wo"] = s.ArgsWO
	}
	stdin, err := json.Marshal(in)
	if err != nil {
		return Result{}, err
	}
	argv := make([]string, 0, len(s.Interpreter)+1)
	for _, a := range s.Interpreter {
		argv = append(argv, ssh.Quote(a))
	}
	res, err := r.Run(ctx, strings.Join(append(argv, ssh.Quote(s.path())), " "), stdin)
	if err != nil {
		return Result{}, err
	}
	var out Result
	jsonErr := json.Unmarshal(res.Stdout, &out)
	switch {
	case jsonErr == nil && out.Error != "":
		return Result{}, fmt.Errorf("the program's %s: %s", mode, out.Error)
	case res.ExitCode != 0:
		return Result{}, fmt.Errorf("the program's %s exited %d: %s", mode, res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	case jsonErr != nil:
		return Result{}, fmt.Errorf("the program's %s didn't print JSON: %v", mode, jsonErr)
	}
	if mode == "plan" && out.InSync == nil {
		return Result{}, errors.New(`the program's plan has no "in_sync"`)
	}
	return out, nil
}

func orEmpty(m json.RawMessage) json.RawMessage {
	if len(m) == 0 {
		return json.RawMessage("{}")
	}
	return m
}
