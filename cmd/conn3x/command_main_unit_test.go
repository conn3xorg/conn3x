// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/command"
)

// unitStdout sends os.Stdout to a file for the test, and returns what was
// written to it when called.
func unitStdout(t *testing.T) func() string {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = f
	t.Cleanup(func() { os.Stdout = old; f.Close() })
	return func() string {
		b, _ := os.ReadFile(f.Name())
		return string(b)
	}
}

// unitTree is a root with a command that runs, one that asks for its
// usage, and one with nothing to run.
func unitTree(ran *bool) command.Command {
	var force bool
	ok := command.Command{Name: "ok", Run: func(command.Meta) int { *ran = true; return 0 }}
	ok.CommandLine.BoolVar(&force, "force", false, "Force it.")
	return command.Command{Commands: []command.Command{
		ok,
		{Name: "usage", Run: func(command.Meta) int { return command.RunResultHelp }},
		{Name: "group"},
	}}
}

// Each subcommand's exit code reaches the caller as an ExitCodeError, and
// one that needs its usage gets it on standard output.
func TestCommandToCliExitCodes(t *testing.T) {
	out := unitStdout(t)
	var ran bool
	meta := func() (command.Meta, int) { return testMeta(t), 0 }
	run := func(args ...string) error {
		return commandToCli("", unitTree(&ran), meta).Run(context.Background(), append([]string{"conn3x"}, args...))
	}
	if err := run("ok", "-force"); err != nil || !ran {
		t.Fatalf("ok: ran %v, %v", ran, err)
	}
	for args, want := range map[string]ExitCodeError{"group": 127, "usage": 1, "ok -nope": 1} {
		var code ExitCodeError
		if err := run(strings.Fields(args)...); !errors.As(err, &code) || code != want {
			t.Errorf("%s: %v, want exit %d", args, err, want)
		}
	}
	if got := out(); !strings.Contains(got, "Usage: conn3x [global options] usage") || !strings.Contains(got, "Usage: conn3x [global options] group") {
		t.Errorf("usage printed:\n%s", got)
	}
	if got := ExitCodeError(3).Error(); got != "3" {
		t.Errorf("ExitCodeError(3).Error() = %q", got)
	}

	// Meta that can't be made stops the command with its code.
	broken := func() (command.Meta, int) { return command.Meta{}, 4 }
	for _, args := range [][]string{{"ok"}, {"ok", "-nope"}} {
		var code ExitCodeError
		if err := commandToCli("", unitTree(&ran), broken).Run(context.Background(), append([]string{"conn3x"}, args...)); !errors.As(err, &code) || code != 4 {
			t.Errorf("%v with broken meta: %v", args, err)
		}
	}
}

// Completion offers the subcommands, flags with the dashes being typed,
// and a command's own arguments.
func TestCompletion(t *testing.T) {
	out := unitStdout(t)
	var ran bool
	root := unitTree(&ran)
	root.Commands[0].AutocompleteArgs = func(command.Meta) func(int) []string {
		return func(int) []string { return []string{"web1", "web2"} }
	}
	meta := func() (command.Meta, int) { return command.Meta{}, 0 }
	for line, want := range map[string][2]string{
		"conn3x us":     {"usage", ""},
		"conn3x ok --":  {"--force", ""},
		"conn3x ok -":   {"-force", "--force"},
		"conn3x ok web": {"web1", ""},
	} {
		t.Setenv("COMP_LINE", line)
		t.Setenv("COMP_POINT", "99")
		r := root
		before := out()
		if !checkAndRunCompletion(&r, meta) {
			t.Fatalf("%s: not completed", line)
		}
		if got := strings.TrimPrefix(out(), before); !strings.Contains(got, want[0]) || (want[1] != "" && strings.Contains(got, want[1])) {
			t.Errorf("%s: completions %q, want %q and not %q", line, got, want[0], want[1])
		}
	}
	// Meta that can't be made completes no arguments.
	t.Setenv("COMP_LINE", "conn3x ok ")
	r := root
	before := out()
	checkAndRunCompletion(&r, func() (command.Meta, int) { return command.Meta{}, 1 })
	if got := strings.TrimPrefix(out(), before); strings.Contains(got, "web1") {
		t.Errorf("completed %q with broken meta", got)
	}

	// Without COMP_LINE nothing completes, and the root asks for its usage,
	// or refuses both autocomplete flags at once.
	t.Setenv("COMP_LINE", "")
	r = root
	if checkAndRunCompletion(&r, meta) {
		t.Fatal("completed without COMP_LINE")
	}
	if code := r.Run(command.Meta{}); code != command.RunResultHelp {
		t.Errorf("root exited %d", code)
	}
	r.CommandLine.ParseLegacy([]string{"-install-autocomplete", "-uninstall-autocomplete"})
	if code := r.Run(command.Meta{}); code != 1 {
		t.Errorf("both autocomplete flags: exit %d", code)
	}
}
