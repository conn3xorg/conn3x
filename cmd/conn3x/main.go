// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Command conn3x provisions and configures infrastructure.
package main

import (
	"fmt"
	"os"

	"github.com/opentofu/opentofu/internal/conn3x/version"
)

func main() {
	args := os.Args[1:]
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version") {
		fmt.Println(version.String())
		return
	}
	fmt.Fprintln(os.Stderr, "conn3x: command not implemented yet")
	os.Exit(2)
}
