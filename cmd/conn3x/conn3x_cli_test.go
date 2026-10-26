// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/command/views"
	"github.com/opentofu/opentofu/internal/command/workdir"
	"github.com/opentofu/opentofu/internal/conn3x/version"
	"github.com/opentofu/opentofu/internal/terminal"
)

func TestHelpUsesConn3xName(t *testing.T) {
	initCommands(command.Meta{})
	got := strings.TrimSpace(helpFunc(commands))
	if !strings.HasPrefix(got, "Usage: conn3x [global options] <subcommand> [args]") {
		t.Fatalf("help starts with %q", strings.SplitN(got, "\n", 2)[0])
	}
}

func TestSubcommandHelpIsBranded(t *testing.T) {
	initCommands(command.Meta{})
	for _, name := range []string{"init", "plan", "apply"} {
		c, err := commands[name]()
		if err != nil {
			t.Fatal(err)
		}
		help := c.Help()
		if !strings.Contains(help, "Usage: conn3x") {
			t.Errorf("%s help has no conn3x usage line:\n%s", name, help)
		}
		if strings.Contains(help, "OpenTofu") || strings.Contains(help, "Usage: tofu") {
			t.Errorf("%s help still mentions OpenTofu or tofu:\n%s", name, help)
		}
	}
}

func TestVersionCommandIsConn3x(t *testing.T) {
	initCommands(command.Meta{})
	c, err := commands["version"]()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.(*conn3xVersionCommand); !ok {
		t.Fatalf("version command is %T", c)
	}
}

func TestVersionLine(t *testing.T) {
	var out strings.Builder
	c := &conn3xVersionCommand{Out: &out}
	if code := c.Run(nil); code != 0 {
		t.Fatalf("version exited %d", code)
	}
	first := strings.SplitN(out.String(), "\n", 2)[0]
	if first != version.String() {
		t.Fatalf("first line %q, want %q", first, version.String())
	}
}

func brandedRoot(t *testing.T) command.Command {
	t.Helper()
	var help, ver bool
	var chdir string
	root := command.RootCommander(&help, &ver, &chdir)
	brandTree(&root)
	return root
}

func findCommand(root command.Command, name string) (command.Command, bool) {
	for _, c := range root.Commands {
		if c.Name == name {
			return c, true
		}
	}
	return command.Command{}, false
}

func TestRootUsageIsBranded(t *testing.T) {
	root := brandedRoot(t)
	usage := commandUsage("", root)
	if !strings.Contains(usage, "Usage: conn3x [global options] <subcommand> [args]") {
		t.Fatalf("root usage:\n%s", usage)
	}
	for _, name := range []string{"init", "plan", "apply", "version"} {
		c, ok := findCommand(root, name)
		if !ok {
			t.Fatalf("no %s command", name)
		}
		u := commandUsage("", c)
		if !strings.Contains(u, "Usage: conn3x [global options] "+name) {
			t.Errorf("%s usage:\n%s", name, u)
		}
		if strings.Contains(u, "OpenTofu") || strings.Contains(u, "Usage: tofu") {
			t.Errorf("%s usage still names OpenTofu or tofu:\n%s", name, u)
		}
	}
}

func TestTreeVersionPrintsConn3x(t *testing.T) {
	root := brandedRoot(t)
	v, ok := findCommand(root, "version")
	if !ok {
		t.Fatal("no version command")
	}
	var out strings.Builder
	old := stdout
	stdout = &out
	t.Cleanup(func() { stdout = old })
	if code := v.Run(command.Meta{}); code != 0 {
		t.Fatalf("version exited %d", code)
	}
	if first := strings.SplitN(out.String(), "\n", 2)[0]; first != version.String() {
		t.Fatalf("first line %q, want %q", first, version.String())
	}
}

// testMeta is enough of a Meta to run a tree command in the current directory.
func testMeta(t *testing.T) command.Meta {
	t.Helper()
	streams, done := terminal.StreamsForTesting(t)
	t.Cleanup(func() { done(t) })
	return command.Meta{View: views.NewView(streams), WorkingDir: workdir.NewDir(".")}
}
