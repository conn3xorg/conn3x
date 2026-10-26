// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/command/views"
	"github.com/opentofu/opentofu/internal/command/workdir"
	"github.com/opentofu/opentofu/internal/conn3x/agent"
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

// stubAgents makes the version command see the given gzipped agents, keyed
// by arch, as if the build embedded them.
func stubAgents(t *testing.T, gz map[string][]byte) {
	t.Helper()
	old := embeddedAgent
	t.Cleanup(func() { embeddedAgent = old })
	embeddedAgent = func(arch string) ([]byte, [32]byte, error) {
		b, ok := gz[arch]
		if !ok {
			return nil, [32]byte{}, agent.ErrUnavailable
		}
		return b, sha256.Sum256(b), nil
	}
}

func TestVersionAgentLine(t *testing.T) {
	amd, arm := []byte("amd64 agent"), []byte("arm64 agent")
	sumAmd, sumArm := sha256.Sum256(amd), sha256.Sum256(arm)
	for name, tc := range map[string]struct {
		gz   map[string][]byte
		want string
	}{
		"both": {map[string][]byte{"amd64": amd, "arm64": arm},
			fmt.Sprintf("agent: linux/amd64 %x, linux/arm64 %x", sumAmd[:6], sumArm[:6])},
		"none": {nil, "agent: none (shell commands only)"},
	} {
		t.Run(name, func(t *testing.T) {
			stubAgents(t, tc.gz)
			var out strings.Builder
			if code := (&conn3xVersionCommand{Out: &out}).Run(nil); code != 0 {
				t.Fatalf("version exited %d", code)
			}
			lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
			if len(lines) != 3 || !strings.HasPrefix(lines[1], "on ") || lines[2] != tc.want {
				t.Fatalf("version printed\n%s\nwant the platform line, then %q", out.String(), tc.want)
			}
		})
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
		// version names the OpenTofu release it is built on, and only that.
		if strings.Contains(strings.ReplaceAll(u, "the OpenTofu release", ""), "OpenTofu") || strings.Contains(u, "Usage: tofu") {
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

func TestVersionHelpNamesOpenTofu(t *testing.T) {
	v, _ := findCommand(brandedRoot(t), "version")
	if u := commandUsage("", v); !strings.Contains(u, "the OpenTofu release it is built on") {
		t.Fatalf("version usage:\n%s", u)
	}
}

func TestVersionJSON(t *testing.T) {
	t.Chdir(t.TempDir())
	v, _ := findCommand(brandedRoot(t), "version")
	var out strings.Builder
	old := stdout
	stdout = &out
	t.Cleanup(func() { stdout = old })
	if code := command.RunCommand(v, testMeta(t), []string{"-json"}); code != 0 {
		t.Fatalf("version -json exited %d", code)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatalf("not JSON: %s\n%s", err, out.String())
	}
	for _, k := range []string{"conn3x_version", "terraform_version", "platform", "provider_selections"} {
		if _, ok := got[k]; !ok {
			t.Errorf("no %q in %s", k, out.String())
		}
	}
	if got["conn3x_version"] != version.Version {
		t.Errorf("conn3x_version = %v, want %s", got["conn3x_version"], version.Version)
	}
}

func TestVersionJSONAgent(t *testing.T) {
	amd := []byte("amd64 agent")
	sum := sha256.Sum256(amd)
	for name, tc := range map[string]struct {
		gz   map[string][]byte
		want any
	}{
		"embedded": {map[string][]byte{"amd64": amd}, map[string]any{"linux/amd64": hex.EncodeToString(sum[:])}},
		"none":     {nil, nil},
	} {
		t.Run(name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			stubAgents(t, tc.gz)
			v, _ := findCommand(brandedRoot(t), "version")
			var out strings.Builder
			old := stdout
			stdout = &out
			t.Cleanup(func() { stdout = old })
			if code := command.RunCommand(v, testMeta(t), []string{"-json"}); code != 0 {
				t.Fatalf("version -json exited %d", code)
			}
			var got map[string]any
			if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
				t.Fatalf("not JSON: %s\n%s", err, out.String())
			}
			a, ok := got["agent"]
			if !ok || !reflect.DeepEqual(a, tc.want) {
				t.Fatalf("agent = %#v (present %v), want %#v", a, ok, tc.want)
			}
		})
	}
}

func TestFmtFormatsCircuits(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	messy := "circuit \"web\" {\nhosts = {}\n}\n"
	for _, name := range []string{"a.circuit.hcl", "b.circuit.hcl"} {
		if err := os.WriteFile(name, []byte(messy), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"a.circuit.hcl"}, nil} {
		if code := command.RunCommand(command.FmtCommander(nil), testMeta(t), args); code != 0 {
			t.Fatalf("fmt %v exited %d", args, code)
		}
	}
	for _, name := range []string{"a.circuit.hcl", "b.circuit.hcl"} {
		got, _ := os.ReadFile(filepath.Join(dir, name))
		if !strings.Contains(string(got), "  hosts = {}") {
			t.Errorf("%s not formatted:\n%s", name, got)
		}
	}
}
