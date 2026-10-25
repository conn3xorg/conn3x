// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/conn3x/convert/ansible"
)

// convertCommand groups the converters from other tools.
func convertCommand() command.Command {
	var playbook, out string
	ans := command.Command{
		Name:  "ansible",
		Short: "Convert an Ansible playbook into circuits",
		Long: `Translates the tasks Conn3x can show mean the same thing into circuit steps, and keeps every other task, commented out with a TODO(convert) line saying why, for you to finish.

Write the result beside the playbook so the files it copies resolve. Exits 0 when every task converted, 3 when some need review, and 1 on errors.`,
	}
	ans.CommandLine.PositionalArg(&playbook, "PLAYBOOK", false)
	ans.CommandLine.StringVar(&out, "out", "", "Write the circuits to this file instead of standard output.")
	ans.Run = func(command.Meta) int { return runConvert(playbook, out, stdout, os.Stderr) }
	return command.Command{
		Name:     "convert",
		Short:    "Convert configuration from another tool into circuits",
		Long:     "Converts configuration written for another tool. Today that is Ansible playbooks.",
		GroupID:  command.OtherCommandGroup.ID,
		Commands: []command.Command{ans},
	}
}

func runConvert(playbook, out string, stdout, stderr io.Writer) int {
	res, err := ansible.Convert(playbook)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %s\n", err)
		return 1
	}
	if out == "" {
		_, err = stdout.Write(res.HCL)
	} else {
		err = os.WriteFile(out, res.HCL, 0o644)
	}
	if err != nil {
		fmt.Fprintf(stderr, "Error: %s\n", err)
		return 1
	}
	total := res.Converted + len(res.Review)
	if len(res.Review) == 0 {
		fmt.Fprintf(stderr, "Converted all %d tasks.\n", total)
		return 0
	}
	fmt.Fprintf(stderr, "Converted %d of %d tasks. %d need you; each is marked TODO(convert):\n", res.Converted, total, len(res.Review))
	for _, r := range res.Review {
		name := r.Task
		if name == "" {
			name = "(unnamed task)"
		}
		fmt.Fprintf(stderr, "  line %d, %s: %s\n", r.Line, name, r.Reason)
	}
	return 3
}
