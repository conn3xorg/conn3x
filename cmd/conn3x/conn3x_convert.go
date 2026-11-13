// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

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

With -out, each role a play runs, from its roles list or an include_role or import_role in its task lists, is converted from roles/ beside the playbook into a circuit directory beside the output file, and called as a module in the order Ansible runs it. A directory that already has files is kept as it is, with a TODO(convert) line in the output file to say this run didn't write it.

With -role, converts one role's directory instead, such as one ansible-galaxy installed, into a new circuit directory named by -out. -role also takes a role on Galaxy, as namespace.name or namespace.name,version, such as geerlingguy.nginx,3.3.1: Conn3x downloads it from GitHub, as ansible-galaxy does, into a temporary directory, and the circuit's README says where it came from. A directory of that name on disk is used instead.

Exits 0 when every task converted, 3 when some need review, and 1 on errors.`,
	}
	// Optional to the parser so runConvert can say what's missing; the
	// usage line still shows it as required.
	ans.CommandLine.PositionalArg(&playbook, "PLAYBOOK", true)
	ans.UsageOverride.Usage = "conn3x [global options] convert ansible [options] <PLAYBOOK>\n       conn3x [global options] convert ansible -role <ROLE> -out <DIR>"
	ans.CommandLine.StringVar(&out, "out", "", "Write the circuits to this file instead of standard output, and the circuits of the roles the playbook runs beside it. With -role, the new directory to write the circuit to.")
	ans.CommandLine.StringVar(&role, "role", "", "Convert the Ansible role in this directory, or this Galaxy role, such as geerlingguy.nginx or geerlingguy.nginx,3.3.1, into a circuit directory.")
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
	// Role directories go beside the file, so they need one.
	opts := ansible.Options{Roles: out != ""}
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
		var kept []string
		kept, err = writeRoles(res.Files, filepath.Dir(out), stderr)
		// Said in the file too: a module block there calls a directory this
		// run didn't write, and the line on stderr is soon gone.
		var note bytes.Buffer
		for _, top := range kept {
			fmt.Fprintf(&note, "# TODO(convert): %s already had files, so this run didn't write it. Check it's the circuit you expect before you apply.\n", top)
		}
		if err == nil {
			err = writeNew(out, append(note.Bytes(), res.HCL...))
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "Error: %s\n", err)
		return 1
	}
	return report(res, stderr, len(res.Files) > 0)
}

// writeNew writes path by renaming a new file over it, so a link already at
// path is replaced rather than written through.
func writeNew(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".conn3x-convert-*")
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(0o644)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}

// writeRoles writes the circuit directory of each role a playbook runs.
// One that already has files is kept as it is, since it may hold edits, and
// returned so the caller can say so.
func writeRoles(files map[string][]byte, dir string, stderr io.Writer) ([]string, error) {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	kept := map[string]bool{}
	var keptDirs []string
	for _, p := range paths {
		top, _, _ := strings.Cut(p, "/")
		if _, done := kept[top]; !done {
			if st, err := os.Lstat(filepath.Join(dir, top)); err == nil && st.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("%s is a link; a role's circuit is written to a directory of its own, so remove the link or convert somewhere else", filepath.Join(dir, top))
			}
			entries, err := os.ReadDir(filepath.Join(dir, top))
			kept[top] = err == nil && len(entries) > 0
			if kept[top] {
				keptDirs = append(keptDirs, top)
				fmt.Fprintf(stderr, "Kept %s, which already has files, so this run didn't write it: check it's the circuit you expect. Convert into a new directory to see the role's circuit as it converts now.\n", top)
			}
		}
		if kept[top] {
			continue
		}
		path := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, files[p], 0o644); err != nil {
			return nil, err
		}
	}
	return keptDirs, nil
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
	var galaxy *ansible.GalaxyRole
	if _, err := os.Stat(role); errors.Is(err, os.ErrNotExist) && ansible.IsGalaxyRole(role) {
		tmp, err := os.MkdirTemp("", "conn3x-galaxy-*")
		if err != nil {
			fmt.Fprintf(stderr, "Error: %s\n", err)
			return 1
		}
		defer os.RemoveAll(tmp)
		g, err := ansible.FetchGalaxyRole(context.Background(), role, tmp)
		if err != nil {
			fmt.Fprintf(stderr, "Error: %s\n", err)
			return 1
		}
		fmt.Fprintf(stderr, "Downloaded %s %s from %s.\n", g.Name, g.Version, g.Repo)
		galaxy, role = &g, g.Dir
	}
	res, err := ansible.ConvertRole(role)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %s\n", err)
		return 1
	}
	if galaxy != nil {
		res.Files["README.md"] = append(res.Files["README.md"], fmt.Sprintf("\n## Source\n\nConverted from the Galaxy role [`%s`](https://galaxy.ansible.com/ui/standalone/roles/%s/), version `%s`, downloaded from %s.\n", galaxy.Name, strings.Replace(galaxy.Name, ".", "/", 1), galaxy.Version, galaxy.Repo)...)
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

// printable shows control and formatting characters as escapes. Task names,
// reasons and file names quote the playbook, which could otherwise move the
// cursor or repaint the summary.
func printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == unicode.ReplacementChar {
			fmt.Fprintf(&b, `\u%04x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func listIssues(stderr io.Writer, issues []ansible.Issue, files bool) {
	for _, r := range issues {
		name := printable(r.Task)
		r.File, r.Reason = printable(r.File), printable(r.Reason)
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
