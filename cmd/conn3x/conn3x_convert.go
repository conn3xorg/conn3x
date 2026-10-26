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
	var playbook, out, inventory string
	ans := command.Command{
		Name:  "ansible",
		Short: "Convert an Ansible playbook into circuits",
		Long: `Translates the tasks Conn3x can show mean the same thing into circuit steps, and keeps every other task, commented out with a TODO(convert) line saying why, for you to finish.

Write the result beside the playbook so the files it copies resolve. With -i, hosts and logins come from the inventory. Exits 0 when every task converted, 3 when some need review, and 1 on errors.`,
	}
	// Optional to the parser so runConvert can say what's missing; the
	// usage line still shows it as required.
	ans.CommandLine.PositionalArg(&playbook, "PLAYBOOK", true)
	ans.UsageOverride.Usage = "conn3x [global options] convert ansible [options] <PLAYBOOK>"
	ans.CommandLine.StringVar(&out, "out", "", "Write the circuits to this file instead of standard output.")
	ans.CommandLine.StringVar(&inventory, "i", "", "Inventory file (INI or YAML) to fill in each play's hosts and login from.")
	ans.CommandLine.StringVar(&inventory, "inventory", "", "Same as -i.")
	ans.Run = func(command.Meta) int { return runConvert(playbook, inventory, out, stdout, os.Stderr) }
	return command.Command{
		Name:     "convert",
		Short:    "Convert configuration from another tool into circuits",
		Long:     "Converts configuration written for another tool. Today that is Ansible playbooks.",
		GroupID:  command.OtherCommandGroup.ID,
		Commands: []command.Command{ans},
	}
}

func runConvert(playbook, inventory, out string, stdout, stderr io.Writer) int {
	if playbook == "" {
		fmt.Fprintln(stderr, "Error: a playbook path is required, as in: conn3x convert ansible site.yml")
		return 1
	}
	var opts ansible.Options
	if inventory != "" {
		inv, err := ansible.ReadInventory(inventory)
		if err != nil {
			fmt.Fprintf(stderr, "Error: %s\n", err)
			return 1
		}
		opts.Inventory = inv
	}
	res, err := ansible.ConvertWith(playbook, opts)
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
	if len(res.Review) == 0 {
		fmt.Fprintf(stderr, "Converted all %d tasks.\n", res.Converted)
		return 0
	}
	things := "things need"
	if len(res.Review) == 1 {
		things = "thing needs"
	}
	fmt.Fprintf(stderr, "Converted %d tasks. %d %s you; each is marked TODO(convert):\n", res.Converted, len(res.Review), things)
	for _, r := range res.Review {
		name := r.Task
		if name == "" {
			name = "(unnamed task)"
		}
		fmt.Fprintf(stderr, "  line %d, %s: %s\n", r.Line, name, r.Reason)
	}
	return 3
}
