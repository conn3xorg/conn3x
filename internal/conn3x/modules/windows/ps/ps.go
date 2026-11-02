// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package ps is the one way Conn3x runs PowerShell on a Windows host.
//
// Every run uses the same command line, whose only payload is a fixed stub.
// The script and its arguments travel as one base64 line on stdin, so no value
// is ever spliced into code or seen on a command line. The stub reads that
// line with $input: reading raw stdin any other way can hang the connection. It
// parses that line with a .NET class, not a cmdlet: where a policy turns on
// PowerShell's module logging, a cmdlet's parameters go to the event log, and
// this line can hold a secret.
//
// The outcome comes only from the stub's last line. The SSH exit status can't
// carry it, because PowerShell as sshd's DefaultShell flattens every failure
// to 1, and stderr may be serialized as CLIXML.
//
// The stub prints a script's objects 64 KiB wide: at the console's width a table
// cuts a long value short, and only a whole value can be blanked afterwards.
// Errors are the exception's message alone, as PowerShell's error view wraps too.
package ps

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Runner runs a command line as given. *ssh.Client satisfies it.
type Runner interface {
	RunRaw(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error)
}

// ReadTimeout limits a read script. Slow roles take seconds, not minutes.
const ReadTimeout = 2 * time.Minute

//go:embed stub.ps1
var stub string

// Command is the command line of every run.
var Command = "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encode(stub)

func encode(s string) string {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(units)*2)
	for _, u := range units {
		b = append(b, byte(u), byte(u>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}

// Script is a module's script, by the name of its embedded file.
type Script struct {
	Name, Body string
}

// Result is what a script produced.
type Result struct {
	Value    json.RawMessage // the script's output as JSON; see User for its own scripts
	Text     string          // User only: the output as PowerShell prints it
	ExitCode int             // $LASTEXITCODE: the last native program's exit status
	Stdout   string          // anything printed outside the output stream
	Stderr   string
}

const resultPrefix = "conn3x-result:"

// NoResultError means the stub never reported: PowerShell didn't start, or
// something on the way failed. A script that threw is a plain error instead.
type NoResultError struct{ Reason string }

func (e *NoResultError) Error() string { return e.Reason }

// Read runs a read_*.ps1 script, which must change nothing on the host.
func Read(ctx context.Context, r Runner, s Script, args map[string]any) (Result, error) {
	if !strings.HasPrefix(s.Name, "read_") {
		return Result{}, fmt.Errorf("%s is not a read script", s.Name)
	}
	return run(ctx, r, s.Body, args, ReadTimeout, false)
}

// Apply runs an apply_*.ps1 script.
func Apply(ctx context.Context, r Runner, s Script, args map[string]any, timeout time.Duration) (Result, error) {
	if !strings.HasPrefix(s.Name, "apply_") {
		return Result{}, fmt.Errorf("%s is not an apply script", s.Name)
	}
	return run(ctx, r, s.Body, args, timeout, false)
}

// User runs a script the user wrote, for windows_powershell alone. Its output
// comes back as Text rather than Value, since serializing whatever a script
// happens to return, such as a list of services, can take minutes. Value holds
// its last output only when that is a boolean. On failure the Result still
// holds what the script printed.
func User(ctx context.Context, r Runner, script string, args map[string]any, timeout time.Duration) (Result, error) {
	return run(ctx, r, script, args, timeout, true)
}

func run(ctx context.Context, r Runner, script string, args map[string]any, timeout time.Duration, text bool) (Result, error) {
	if args == nil {
		args = map[string]any{}
	}
	in, err := json.Marshal(map[string]any{"script": script, "args": args, "text": text})
	if err != nil {
		return Result{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, err := r.RunRaw(ctx, Command, []byte(base64.StdEncoding.EncodeToString(in)+"\n"))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return Result{}, &NoResultError{fmt.Sprintf("PowerShell did not finish within %s", timeout)}
		}
		return Result{}, &NoResultError{err.Error()}
	}
	return parse(res)
}

func parse(res ssh.Result) (Result, error) {
	out := Result{Stderr: cleanStderr(res.Stderr)}
	stdout := bytes.ReplaceAll(res.Stdout, []byte("\r\n"), []byte("\n"))
	i := bytes.LastIndex(stdout, []byte(resultPrefix))
	if i < 0 || (i > 0 && stdout[i-1] != '\n') {
		out.Stdout = string(stdout)
		msg := strings.TrimSpace(out.Stderr)
		if msg == "" {
			msg = strings.TrimSpace(out.Stdout)
		}
		return out, &NoResultError{fmt.Sprintf("PowerShell gave no result (exit status %d), so this may not be a Windows host: %s", res.ExitCode, msg)}
	}
	out.Stdout = string(stdout[:i])
	line, _, _ := bytes.Cut(stdout[i+len(resultPrefix):], []byte("\n"))
	raw, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(line)))
	if err != nil {
		return out, &NoResultError{"reading PowerShell's result: " + err.Error()}
	}
	var r struct {
		OK    bool            `json:"ok"`
		Value json.RawMessage `json:"value"`
		Text  string          `json:"text"`
		RC    int             `json:"rc"`
		Error string          `json:"error"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return out, &NoResultError{"reading PowerShell's result: " + err.Error()}
	}
	out.Value, out.Text, out.ExitCode = r.Value, r.Text, r.RC
	if !r.OK {
		return out, errors.New(strings.TrimSpace(r.Error))
	}
	return out, nil
}

var (
	clixmlString = regexp.MustCompile(`(?s)<S S="[^"]*">(.*?)</S>`)
	clixmlEscape = regexp.MustCompile(`_x([0-9A-Fa-f]{4})_`)
)

// cleanStderr turns stderr serialized as CLIXML back into plain text.
func cleanStderr(b []byte) string {
	s := string(b)
	if !strings.HasPrefix(strings.TrimSpace(s), "#< CLIXML") {
		return s
	}
	var out strings.Builder
	for _, m := range clixmlString.FindAllStringSubmatch(s, -1) {
		out.WriteString(html.UnescapeString(m[1]))
	}
	return clixmlEscape.ReplaceAllStringFunc(out.String(), func(e string) string {
		var r rune
		_, _ = fmt.Sscanf(e, "_x%04x_", &r)
		return string(r)
	})
}
