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
	cmd := fmt.Sprintf(modules.Sum256+`p=%[1]s; if [ -f "$p" ] && [ "$(sum256 "$p")" = %[2]s ]; then exit 0; fi
install -d -m 0700 %[3]s || exit 1
t=$(mktemp %[3]s/.new.XXXXXX) || exit 1
trap 'rm -f "$t"' EXIT
cat > "$t" && chmod 0700 "$t" && [ "$(sum256 "$t")" = %[2]s ] && mv -f "$t" "$p" || { echo "the program didn't arrive whole" >&2; exit 1; }
trap - EXIT`,
		p, ssh.Quote(s.Sum()), ssh.Quote(Dir))
	res, err := r.Run(ctx, cmd, s.Program)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("copying the program to %s: %s. A script step needs become, or a login that can write %s", Dir, strings.TrimSpace(string(res.Stderr)), Dir)
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
	// What the program returns is saved in state and shown in the plan, so
	// a write-only value in it would undo args_wo. Refuse it unsaved.
	if secrets := stringsIn(s.ArgsWO); len(secrets) > 0 {
		for _, field := range [...]json.RawMessage{out.State, out.Changes} {
			for v := range stringsIn(field) {
				if holdsSecret(v, secrets) {
					return Result{}, fmt.Errorf("the program's %s returned an args_wo value in its state or changes, which Conn3x would store; it wasn't saved", mode)
				}
			}
		}
	}
	return out, nil
}

// minEmbedded is the shortest args_wo value looked for inside a longer
// string, such as TOKEN=... or a URL's password. Shorter ones, like "on",
// would refuse almost anything, so they only match a whole string.
const minEmbedded = 6

func holdsSecret(v string, secrets map[string]bool) bool {
	for secret := range secrets {
		if v == secret || len(secret) >= minEmbedded && strings.Contains(v, secret) {
			return true
		}
	}
	return false
}

// stringsIn is every non-empty string value in a JSON document, as a set.
func stringsIn(doc json.RawMessage) map[string]bool {
	out := map[string]bool{}
	if len(doc) == 0 {
		return out
	}
	var v any
	if json.Unmarshal(doc, &v) != nil {
		return out
	}
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case string:
			if v != "" {
				out[v] = true
			}
		case []any:
			for _, e := range v {
				walk(e)
			}
		case map[string]any:
			for _, e := range v {
				walk(e)
			}
		}
	}
	walk(v)
	return out
}

func orEmpty(m json.RawMessage) json.RawMessage {
	if len(m) == 0 {
		return json.RawMessage("{}")
	}
	return m
}
