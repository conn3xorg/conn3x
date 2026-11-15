// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"os"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/conn3x/provider"
)

func init() {
	command.ExtraInternalProviders["conn3x"] = provider.New
}

// finish runs as the command exits, with its exit code. A failed apply never
// closes its providers, so this is where a config session an EOS step left
// staged is aborted, and where the user hears what that left on a switch.
// Then the SSH connections close, and with them any proxy_command.
func finish(code int) int {
	defer provider.ClosePool()
	if err := provider.FinishEOS(); err != nil {
		fmt.Fprintf(os.Stderr, "\nError: %s\n", err)
		return max(code, 1)
	}
	return code
}
