// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/conn3x/mcp"
	"github.com/opentofu/opentofu/internal/conn3x/version"
)

func mcpCommand() command.Command {
	cmd := command.Command{
		Name:  "mcp",
		Short: "Serve Conn3x's modules, circuits and checks to an AI assistant",
		Long: `Starts a Model Context Protocol server on standard input and output, for an assistant to look up Conn3x's modules and official circuits, validate and lint a circuit, and summarise a saved plan. Nothing it does applies anything or writes state.

Add it to an assistant's MCP servers as the command conn3x with the argument mcp.

Tools:
  search_modules   find modules by name or words in their description
  module_docs      one module's arguments, as on its page on docs.conn3x.org
  search_circuits  find official circuits, with grade and latest version (reads https://conn3x.org/circuits.json)
  validate         conn3x validate on a directory
  lint             conn3x lint on a directory
  summarise_plan   what a saved plan would change on each host, without any values`,
		GroupID: command.OtherCommandGroup.ID,
	}
	cmd.Run = func(command.Meta) int {
		self, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: finding the conn3x binary: %s\n", err)
			return 1
		}
		s := &mcp.Server{Name: "conn3x", Version: version.Version, Tools: mcp.Tools(self)}
		if err := s.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
		return 0
	}
	return cmd
}
