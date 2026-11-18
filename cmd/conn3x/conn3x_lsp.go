// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/conn3x/lsp"
	"github.com/opentofu/opentofu/internal/conn3x/version"
)

func lspCommand() command.Command {
	cmd := command.Command{
		Name:  "lsp",
		Short: "Serve completion, hover docs and validation for circuit files to an editor",
		Long: `Starts a Language Server Protocol server on standard input and output, for editors other than VS Code (which has the Conn3x extension): Neovim, Helix, Zed, Emacs, JetBrains IDEs with an LSP plugin, and the like.

Inside a step it completes the step modules, and inside a module its arguments, required ones first, leaving out those already set. Hover shows a module's or an argument's description, with a link to its page. When a file is saved it runs conn3x validate in that file's directory and shows the errors in the editor; a directory that hasn't had conn3x init yet is left alone. Completion and hover come from this conn3x binary's own modules, so they match what it accepts.

Point your editor's language server for .circuit.hcl files at the command conn3x with the argument lsp.`,
		GroupID: command.OtherCommandGroup.ID,
	}
	cmd.Run = func(command.Meta) int {
		self, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: finding the conn3x binary: %s\n", err)
			return 1
		}
		s := &lsp.Server{Name: "conn3x", Version: version.Version, Self: self}
		if err := s.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
		return 0
	}
	return cmd
}
