// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/conn3x/lint"
)

func lintCommand() command.Command {
	var dirs []string
	var asJSON bool
	cmd := command.Command{
		Name:  "lint",
		Short: "Check circuits for what the circuit grader marks down",
		Long: `Reads the .hcl, .tf and .sh files in each directory (the current one by default), leaving out examples/ and test/, and reports one line per finding:

  main.circuit.hcl:12:7: C3X001 download-checksum: download step has no sha256, ...

Rules:
  C3X001 download-checksum  a download step, or a windows_package with a url, without sha256
  C3X002 image-digest       a container image with a tag and no digest
  C3X003 listen-all         a default or literal that listens on every address
  C3X004 privileged-shell   shell that's wrong wherever it runs as root, such as curl | sh
  C3X101 command-guard      a command step with no creates, removes, unless or triggers (a warning)
  C3X900 ignore             an ignore with no reason, or one that matches nothing

C3X001 to C3X004 are the circuit grader's checks of a circuit's own code, with the same patterns, so a circuit that lints clean passes them.

To keep a finding you've looked at, say why on its line or the line above:

  # conn3x-lint:ignore C3X003 the caller sets listen_address; this is the documented default

Exits 1 when any finding is an error, and 0 otherwise.`,
		GroupID: command.OtherCommandGroup.ID,
	}
	cmd.CommandLine.VariadicArg(&dirs, "DIR")
	cmd.CommandLine.BoolVar(&asJSON, "json", false, "Print the findings as a JSON array.")
	cmd.UsageOverride.Usage = "conn3x [global options] lint [-json] [DIR ...]"
	cmd.Run = func(command.Meta) int {
		return runLint(dirs, asJSON, stdout, os.Stderr)
	}
	return cmd
}

func runLint(dirs []string, asJSON bool, stdout, stderr io.Writer) int {
	if len(dirs) == 0 {
		dirs = []string{"."}
	}
	var all []lint.Finding
	for _, d := range dirs {
		found, err := lint.Dir(d)
		if err != nil {
			fmt.Fprintf(stderr, "Error: %s\n", err)
			return 1
		}
		all = append(all, found...)
	}
	if asJSON {
		if all == nil {
			all = []lint.Finding{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(all); err != nil {
			fmt.Fprintf(stderr, "Error: %s\n", err)
			return 1
		}
	} else {
		for _, f := range all {
			fmt.Fprintln(stdout, f.String())
		}
	}
	if lint.Failed(all) {
		return 1
	}
	return 0
}
