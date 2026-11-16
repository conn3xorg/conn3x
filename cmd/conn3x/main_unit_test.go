// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/addrs"
)

func TestParseReattachProviders(t *testing.T) {
	got, err := parseReattachProviders(`{
		"registry.opentofu.org/conn3xorg/conn3x": {"Protocol": "grpc", "ProtocolVersion": 6, "Pid": 42, "Test": true, "Addr": {"Network": "unix", "String": "/tmp/plugin.sock"}},
		"example.com/a/b": {"Protocol": "grpc", "ProtocolVersion": 5, "Addr": {"Network": "tcp", "String": "127.0.0.1:1234"}}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	c := got[addrs.MustParseProviderSourceString("conn3xorg/conn3x")]
	if len(got) != 2 || c == nil || c.Pid != 42 || !c.Test || c.ProtocolVersion != 6 || c.Addr.String() != "/tmp/plugin.sock" {
		t.Fatalf("got %+v", got)
	}
	if tcp := got[addrs.MustParseProviderSourceString("example.com/a/b")]; tcp == nil || tcp.Addr.Network() != "tcp" {
		t.Errorf("tcp provider: %+v", tcp)
	}
	if got, err := parseReattachProviders(""); err != nil || len(got) != 0 {
		t.Errorf("unset: %v, %v", got, err)
	}
	for in, want := range map[string]string{
		`[`:                                 "Invalid format for TF_REATTACH_PROVIDERS",
		`{"not a/valid/provider/addr": {}}`: "as a provider address",
		`{"a/b": {"Addr": {"Network": "tcp", "String": "nope"}}}`: "Invalid TCP address",
		`{"a/b": {"Addr": {"Network": "pipe"}}}`:                  `Unknown address type "pipe"`,
	} {
		if _, err := parseReattachProviders(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", in, err, want)
		}
	}
}

func TestStartTrace(t *testing.T) {
	t.Setenv(envTrace, "")
	stop, err := startTrace()
	if err != nil {
		t.Fatal(err)
	}
	stop()

	path := filepath.Join(t.TempDir(), "trace.out")
	t.Setenv(envTrace, path)
	stop, err = startTrace()
	if err != nil {
		t.Fatal(err)
	}
	// Only one trace runs at a time.
	if _, err := startTrace(); err == nil || !strings.Contains(err.Error(), "could not start "+envTrace) {
		t.Errorf("a second trace: %v", err)
	}
	stop()
	if st, err := os.Stat(path); err != nil || st.Size() == 0 {
		t.Errorf("trace file: %v, %v", st, err)
	}

	t.Setenv(envTrace, filepath.Join(path, "under-a-file"))
	if _, err := startTrace(); err == nil || !strings.Contains(err.Error(), "could not open "+envTrace) {
		t.Errorf("an unwritable path: %v", err)
	}
}

// realMain runs a command, through the new CLI or the legacy one, with the
// profile, trace and log the environment asks for, and exits 1 when one of
// them, or the extra arguments in TF_CLI_ARGS, can't be had.
func TestRealMainEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOME", dir)
	var out strings.Builder
	oldOut, oldArgs, oldCommands := stdout, os.Args, commands
	stdout = &out
	t.Cleanup(func() { stdout, os.Args, commands = oldOut, oldArgs, oldCommands })
	os.Args = []string{"conn3x", "version"}
	commands = nil // another test's commands write to its own output

	logPath, profile := filepath.Join(dir, "tmp.log"), filepath.Join(dir, "cpu.prof")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, cli := range []string{"", "false"} {
		t.Run("cli="+cli, func(t *testing.T) {
			t.Setenv(EnvCliEnabled, cli)
			t.Setenv(EnvCPUProfile, profile)
			t.Setenv(envTmpLogPath, logPath)
			t.Setenv("GODEBUG", "panicnil=0")
			out.Reset()
			legacyOut := unitStdout(t) // the legacy CLI prints to os.Stdout itself
			if code := realMain(); code != 0 || !strings.Contains(out.String()+legacyOut(), "Conn3x v") {
				t.Fatalf("exit %d, out %q", code, out.String()+legacyOut())
			}
			if st, err := os.Stat(profile); err != nil || st.Size() == 0 {
				t.Errorf("cpu profile: %v, %v", st, err)
			}

			for env, val := range map[string]string{
				EnvCPUProfile:           filepath.Join(dir, "missing", "cpu.prof"),
				envTrace:                filepath.Join(dir, "missing", "trace.out"),
				"TF_REATTACH_PROVIDERS": "[",
				EnvCLI:                  "'unterminated",
				EnvCLI + "_version":     "'unterminated",
			} {
				t.Run(env, func(t *testing.T) {
					t.Setenv(env, val)
					if code := realMain(); code != 1 {
						t.Errorf("%s=%s: exit %d", env, val, code)
					}
				})
			}
		})
	}
}
