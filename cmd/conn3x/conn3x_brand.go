// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mitchellh/cli"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/command/arguments"
	"github.com/opentofu/opentofu/internal/conn3x/agent"
	"github.com/opentofu/opentofu/internal/conn3x/version"
	"github.com/opentofu/opentofu/internal/getproviders"
	"github.com/opentofu/opentofu/internal/tfdiags"
	tfversion "github.com/opentofu/opentofu/version"
)

// The subcommands come from OpenTofu and describe themselves as such.
// brand rewrites their help text so the CLI speaks as conn3x.
var helpBrand = strings.NewReplacer(
	// Comparisons go in argument order, so this keeps the version help's
	// one true mention of OpenTofu.
	"the OpenTofu release", "the OpenTofu release",
	"OpenTofu", "Conn3x",
	"Usage: tofu ", "Usage: conn3x ",
	"tofu -help", "conn3x -help",
	"`tofu ", "`conn3x ",
	" tofu ", " conn3x ",
	"\ttofu ", "\tconn3x ",
)

type brandedCommand struct{ cli.Command }

func (c brandedCommand) Help() string     { return helpBrand.Replace(c.Command.Help()) }
func (c brandedCommand) Synopsis() string { return helpBrand.Replace(c.Command.Synopsis()) }

// brandCommands wraps every factory so its help and synopsis are branded,
// and replaces the version command with conn3x's own.
func brandCommands(cmds map[string]cli.CommandFactory, out io.Writer) {
	for name, factory := range cmds {
		factory := factory
		cmds[name] = func() (cli.Command, error) {
			c, err := factory()
			if err != nil || c == nil {
				return c, err
			}
			return brandedCommand{c}, nil
		}
	}
	cmds["version"] = func() (cli.Command, error) {
		return &conn3xVersionCommand{Out: out}, nil
	}
}

type conn3xVersionCommand struct {
	Out io.Writer
}

func (c *conn3xVersionCommand) Run([]string) int {
	fmt.Fprintln(c.Out, version.String())
	fmt.Fprintf(c.Out, "on %s\n", getproviders.CurrentPlatform)
	sums := agentSums()
	if sums == nil {
		fmt.Fprintln(c.Out, "agent: none (shell commands only)")
		return 0
	}
	var parts []string
	for _, p := range agentPlatforms {
		if sum, ok := sums[p]; ok {
			parts = append(parts, p+" "+sum[:12])
		}
	}
	fmt.Fprintln(c.Out, "agent: "+strings.Join(parts, ", "))
	return 0
}

// embeddedAgent is where the version command looks for agents; tests swap it.
var embeddedAgent = agent.Embedded

var agentPlatforms = []string{"linux/amd64", "linux/arm64"}

// agentSums maps each platform this build embeds an agent for to the
// sha256 of that agent, or is nil when it embeds none.
func agentSums() map[string]string {
	var sums map[string]string
	for _, p := range agentPlatforms {
		_, sum, err := embeddedAgent(strings.TrimPrefix(p, "linux/"))
		if err != nil {
			continue
		}
		if sums == nil {
			sums = map[string]string{}
		}
		sums[p] = hex.EncodeToString(sum[:])
	}
	return sums
}

func (c *conn3xVersionCommand) Help() string {
	return "Usage: conn3x [global options] version\n\n  Displays the version of Conn3x and the OpenTofu release it is built on.\n"
}

func (c *conn3xVersionCommand) Synopsis() string {
	return "Show the current Conn3x version"
}

// versionJSON prints version -json: OpenTofu's fields, plus conn3x_version
// and agent.
type versionJSON struct{ out io.Writer }

func (versionJSON) Diagnostics(tfdiags.Diagnostics) {}

func (v versionJSON) PrintVersion(tofu, prerelease, platform string, fips bool, providers map[string]string) bool {
	if prerelease != "" {
		tofu += "-" + prerelease
	}
	b, err := json.MarshalIndent(struct {
		Conn3x    string            `json:"conn3x_version"`
		Tofu      string            `json:"terraform_version"`
		Platform  string            `json:"platform"`
		FIPS      bool              `json:"fips140,omitempty"`
		Providers map[string]string `json:"provider_selections"`
		Agent     map[string]string `json:"agent"`
	}{version.Version, tofu, platform, fips, providers, agentSums()}, "", "  ")
	if err != nil {
		return false
	}
	_, err = fmt.Fprintln(v.out, string(b))
	return err == nil
}

// stdout is where the conn3x version command writes; tests replace it.
var stdout io.Writer = os.Stdout

// brandTree rewrites the help text of the OpenTofu command tree so it names
// conn3x, and swaps in the conn3x version command.
func brandTree(cmd *command.Command) {
	cmd.Short = helpBrand.Replace(cmd.Short)
	cmd.Long = helpBrand.Replace(cmd.Long)
	if cmd.UsageOverride.Usage != "" {
		cmd.UsageOverride.Usage = strings.Replace(cmd.UsageOverride.Usage, "tofu ", "conn3x ", 1)
	}
	if cmd.Name == "version" {
		cmd.Short = "Show the current Conn3x version"
		cmd.Long = "Displays the version of Conn3x and the OpenTofu release it is built on."
		view := cmd.CommandLine.View
		cmd.Run = func(m command.Meta) int {
			if view.ViewType == arguments.ViewJSON {
				return command.VersionCommand{
					Meta:              m,
					Version:           tfversion.Version,
					VersionPrerelease: tfversion.Prerelease,
					Platform:          getproviders.CurrentPlatform,
				}.Execute(versionJSON{stdout})
			}
			return (&conn3xVersionCommand{Out: stdout}).Run(nil)
		}
	}
	if cmd.Name == "init" && cmd.Run != nil {
		cmd.Run = suggestEncryption(cmd.Run, cmd.CommandLine.View)
	}
	for i := range cmd.Commands {
		brandTree(&cmd.Commands[i])
	}
	if cmd.Name == "" {
		cmd.Commands = append(cmd.Commands, driftCommand(), convertCommand())
	}
}

// commandUsage renders a command's usage text as conn3x.
func commandUsage(namespace string, cmd command.Command) string {
	var b strings.Builder
	command.CommandUsage(namespace, cmd, &b)
	return helpBrand.Replace(b.String())
}

// brandWriter applies helpBrand to usage text written straight to a stream.
type brandWriter struct{ w io.Writer }

func (b brandWriter) Write(p []byte) (int, error) {
	if _, err := io.WriteString(b.w, helpBrand.Replace(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}
