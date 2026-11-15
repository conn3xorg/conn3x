// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import "strconv"

// defaultParallelism is the -parallelism the commands below get unless the
// command line or TF_CLI_ARGS sets one. OpenTofu's 10 suits cloud APIs with
// rate limits; each host behind SSH is its own server, and over a network
// 10 at once leaves a fleet's plan waiting on round trips: 44 s for 500
// hosts at 10, 11 s at 50 (#524). Logins through one jump host are held
// under its sshd's MaxStartups by the SSH transport itself.
const defaultParallelism = 50

var parallelismCommands = map[string]bool{"plan": true, "apply": true, "destroy": true, "refresh": true, "import": true}

// withDefaultParallelism puts -parallelism right after the subcommand, ahead
// of TF_CLI_ARGS and the user's own flags, so either of those still wins.
func withDefaultParallelism(cmd string, args []string) []string {
	if !parallelismCommands[cmd] {
		return args
	}
	for i, a := range args {
		if a == cmd {
			out := make([]string, 0, len(args)+1)
			out = append(out, args[:i+1]...)
			out = append(out, "-parallelism="+strconv.Itoa(defaultParallelism))
			return append(out, args[i+1:]...)
		}
	}
	return args
}
