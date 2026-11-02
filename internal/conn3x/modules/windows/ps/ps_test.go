// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ps

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// fake answers every run with a canned result and keeps what it was sent.
type fake struct {
	cmd      string
	stdin    []byte
	res      ssh.Result
	deadline bool
}

func (f *fake) RunRaw(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	f.cmd, f.stdin = cmd, stdin
	_, f.deadline = ctx.Deadline()
	return f.res, nil
}

func line(v map[string]any) string {
	b, _ := json.Marshal(v)
	return resultPrefix + base64.StdEncoding.EncodeToString(b)
}

func TestCommandFitsCmdExeAndHoldsTheStub(t *testing.T) {
	if len(Command) > 8000 {
		t.Errorf("command line is %d characters; cmd.exe allows 8191", len(Command))
	}
	raw, err := base64.StdEncoding.DecodeString(Command[strings.LastIndex(Command, " ")+1:])
	if err != nil {
		t.Fatal(err)
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	if got := string(utf16.Decode(units)); got != stub {
		t.Errorf("decoded stub differs:\n%s", got)
	}
}

// The stub is the only place code is made from a string, and it reads stdin
// only through $input, the one way that doesn't hang.
func TestStubShape(t *testing.T) {
	if n := strings.Count(stub, "[scriptblock]::Create"); n != 1 {
		t.Errorf("[scriptblock]::Create appears %d times", n)
	}
	for _, banned := range []string{"OpenStandardInput", "CopyTo", "[Console]::In", "Invoke-Expression"} {
		if strings.Contains(stub, banned) {
			t.Errorf("the stub uses %s", banned)
		}
	}
	if !strings.Contains(stub, "@($input)") {
		t.Error("the stub doesn't read $input")
	}
}

func TestValuesTravelOnlyOnStdinAsOneLine(t *testing.T) {
	f := &fake{res: ssh.Result{Stdout: []byte(line(map[string]any{"ok": true}))}}
	hostile := "'; Remove-Item C:\\ -Recurse; $(whoami) `n"
	if _, err := Read(context.Background(), f, Script{Name: "read_x.ps1", Body: "param($A) $A.v"}, map[string]any{"v": hostile}); err != nil {
		t.Fatal(err)
	}
	if f.cmd != Command {
		t.Error("the command line changed with the values")
	}
	if !f.deadline {
		t.Error("no deadline on the run")
	}
	if n := strings.Count(string(f.stdin), "\n"); n != 1 || f.stdin[len(f.stdin)-1] != '\n' {
		t.Errorf("stdin has %d newlines: %q", n, f.stdin)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(f.stdin)))
	if err != nil {
		t.Fatal(err)
	}
	var in struct {
		Script string
		Args   map[string]string
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	if in.Args["v"] != hostile || strings.Contains(in.Script, "Remove-Item") {
		t.Errorf("sent %+v", in)
	}
}

func TestReadAndApplyTakeOnlyTheirOwnScripts(t *testing.T) {
	f := &fake{}
	if _, err := Read(context.Background(), f, Script{Name: "apply_x.ps1"}, nil); err == nil {
		t.Error("Read ran an apply script")
	}
	if _, err := Apply(context.Background(), f, Script{Name: "read_x.ps1"}, nil, time.Minute); err == nil {
		t.Error("Apply ran a read script")
	}
	if f.cmd != "" {
		t.Error("something reached the host")
	}
}

func TestParse(t *testing.T) {
	for name, tc := range map[string]struct {
		res              ssh.Result
		wantErr, wantOut string
		wantValue        string
		wantExit         int
	}{
		"stray output and CRLF": {
			res:       ssh.Result{Stdout: []byte("noise\r\n" + line(map[string]any{"ok": true, "value": 5, "rc": 3}) + "\r\n"), ExitCode: 1},
			wantOut:   "noise\n",
			wantValue: "5",
			wantExit:  3,
		},
		"exit status doesn't count": {
			res:       ssh.Result{Stdout: []byte(line(map[string]any{"ok": true, "value": true})), ExitCode: 255},
			wantValue: "true",
		},
		"failure from the line, even with exit 0": {
			res:     ssh.Result{Stdout: []byte(line(map[string]any{"ok": false, "error": "boom\r\n"}))},
			wantErr: "boom",
		},
		"the last line wins": {
			res:       ssh.Result{Stdout: []byte(line(map[string]any{"ok": false}) + "\n" + line(map[string]any{"ok": true, "value": 1}))},
			wantValue: "1",
			wantOut:   line(map[string]any{"ok": false}) + "\n",
		},
		"no line": {
			res:     ssh.Result{Stderr: []byte("sh: powershell.exe: not found\n"), ExitCode: 127},
			wantErr: "may not be a Windows host: sh: powershell.exe: not found",
		},
		"not at the start of a line": {
			res:     ssh.Result{Stdout: []byte("x" + line(map[string]any{"ok": true}))},
			wantErr: "gave no result",
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parse(tc.res)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatal(err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("err = %v", err)
			}
			if tc.wantErr != "" {
				return
			}
			if got.Stdout != tc.wantOut || string(got.Value) != tc.wantValue || got.ExitCode != tc.wantExit {
				t.Errorf("got %+v", got)
			}
		})
	}
}

func TestCleanStderr(t *testing.T) {
	in := "#< CLIXML\r\n<Objs Version=\"1.1\"><S S=\"Error\">oh &lt;no&gt;_x000D__x000A_</S><S S=\"warning\">again</S></Objs>"
	if got := cleanStderr([]byte(in)); got != "oh <no>\r\nagain" {
		t.Errorf("got %q", got)
	}
	if got := cleanStderr([]byte("plain _x000D_")); got != "plain _x000D_" {
		t.Errorf("plain stderr changed: %q", got)
	}
}
