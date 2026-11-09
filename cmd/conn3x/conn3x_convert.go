// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/conn3x/convert/ansible"
)

// convertCommand groups the converters from other tools.
func convertCommand() command.Command {
	var playbook, out, inventory, role string
	ans := command.Command{
		Name:  "ansible",
		Short: "Convert an Ansible playbook into circuits",
		Long: `Translates the tasks Conn3x can show mean the same thing into circuit steps, and keeps every other task, commented out with a TODO(convert) line saying why, for you to finish.

Write the result beside the playbook so the files it copies resolve. With -i, hosts and logins come from the inventory.

With -role, converts one role's directory instead, such as one ansible-galaxy installed, into a new circuit directory named by -out. Nothing is downloaded: install a role from Galaxy yourself, with ansible-galaxy, then point -role at it.

Exits 0 when every task converted, 3 when some need review, and 1 on errors.`,
	}
	// Optional to the parser so runConvert can say what's missing; the
	// usage line still shows it as required.
	ans.CommandLine.PositionalArg(&playbook, "PLAYBOOK", true)
	ans.UsageOverride.Usage = "conn3x [global options] convert ansible [options] <PLAYBOOK>\n       conn3x [global options] convert ansible -role <ROLE> -out <DIR>"
	ans.CommandLine.StringVar(&out, "out", "", "Write the circuits to this file instead of standard output. With -role, the new directory to write the circuit to.")
	ans.CommandLine.StringVar(&role, "role", "", "Convert the Ansible role in this directory into a circuit directory.")
	ans.CommandLine.StringVar(&inventory, "i", "", "Inventory file (INI or YAML) to fill in each play's hosts and login from.")
	ans.CommandLine.StringVar(&inventory, "inventory", "", "Same as -i.")
	ans.Run = func(command.Meta) int {
		if role != "" {
			return runConvertRole(role, out, playbook, inventory, os.Stderr)
		}
		return runConvert(playbook, inventory, out, stdout, os.Stderr)
	}
	return command.Command{
		Name:     "convert",
		Short:    "Convert configuration from another tool into circuits",
		Long:     "Converts configuration written for another tool. Today that is Ansible playbooks and roles.",
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
	return report(res, stderr, false)
}

// runConvertRole converts a role into a new circuit directory. It never
// writes into a directory that already has files, so nothing is replaced.
func runConvertRole(role, out, playbook, inventory string, stderr io.Writer) int {
	switch {
	case playbook != "":
		fmt.Fprintln(stderr, "Error: give a playbook or -role, not both")
		return 1
	case inventory != "":
		fmt.Fprintln(stderr, "Error: -i doesn't go with -role: a role has no hosts of its own, so set them where you call its circuit")
		return 1
	case out == "":
		fmt.Fprintln(stderr, "Error: -role needs -out, the new directory to write the circuit to, as in: conn3x convert ansible -role roles/web -out circuit-web")
		return 1
	}
	if entries, err := os.ReadDir(out); err == nil && len(entries) > 0 {
		fmt.Fprintf(stderr, "Error: %s already has files in it; choose a new directory, so nothing in it is replaced\n", out)
		return 1
	}
	res, err := ansible.ConvertRole(role)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %s\n", err)
		return 1
	}
	for p, b := range res.Files {
		path := filepath.Join(out, filepath.FromSlash(p))
		err := os.MkdirAll(filepath.Dir(path), 0o755)
		if err == nil {
			err = os.WriteFile(path, b, 0o644)
		}
		if err != nil {
			fmt.Fprintf(stderr, "Error: %s\n", err)
			return 1
		}
	}
	return report(res, stderr, true)
}

// report says what converted and lists what's left, returning the exit code.
// Notes on converted steps are listed too, but leave the exit code alone.
func report(res ansible.Result, stderr io.Writer, files bool) int {
	code := 0
	if len(res.Review) == 0 {
		if res.Converted == 1 {
			fmt.Fprintln(stderr, "Converted the 1 task.")
		} else {
			fmt.Fprintf(stderr, "Converted all %d tasks.\n", res.Converted)
		}
	} else {
		things := "things need"
		if len(res.Review) == 1 {
			things = "thing needs"
		}
		fmt.Fprintf(stderr, "Converted %d tasks. %d %s you; each is marked TODO(convert):\n", res.Converted, len(res.Review), things)
		listIssues(stderr, res.Review, files)
		code = 3
	}
	if len(res.Notes) > 0 {
		steps := "converted steps have a note"
		if len(res.Notes) == 1 {
			steps = "converted step has a note"
		}
		fmt.Fprintf(stderr, "%d %s to act on once, also marked TODO(convert):\n", len(res.Notes), steps)
		listIssues(stderr, res.Notes, files)
	}
	return code
}

func listIssues(stderr io.Writer, issues []ansible.Issue, files bool) {
	for _, r := range issues {
		name := r.Task
		if name == "" {
			name = "(unnamed task)"
		}
		switch {
		case files && r.Line > 0:
			fmt.Fprintf(stderr, "  %s line %d, %s: %s\n", r.File, r.Line, name, r.Reason)
		case files:
			fmt.Fprintf(stderr, "  %s, %s: %s\n", r.File, name, r.Reason)
		default:
			fmt.Fprintf(stderr, "  line %d, %s: %s\n", r.Line, name, r.Reason)
		}
	}
}
