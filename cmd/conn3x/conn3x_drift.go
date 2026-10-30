// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/command/arguments"
	"github.com/opentofu/opentofu/internal/conn3x/provider"
)

// driftCommand reports what changed outside Conn3x since the last apply,
// split into the cloud resources and the host steps. It runs a refresh-only
// plan and exits 2 when anything drifted, like plan -detailed-exitcode. Cloud
// APIs also change values nobody set, such as a table's row count, so a cloud
// resource only counts when a normal plan would change it back.
func driftCommand() command.Command {
	cmd := command.Command{
		Name:  "drift",
		Short: "Report what changed outside Conn3x, in the cloud and on hosts",
		Long: `Reads every resource and host step again and reports what no longer matches the last apply, grouped into cloud resources and host steps. Nothing is changed.

A cloud resource whose changes your config wouldn't undo, such as a table's row count, is listed but isn't drift.

Exits 0 when nothing drifted, 2 when something did, and 1 on errors. It takes the same options as plan, except -json: for machine-readable drift, run plan -refresh-only -json.`,
		GroupID: command.MainCommandGroup.ID,
	}
	// Declaring plan's options lets the CLI accept them; the refresh-only
	// plan run below parses them for real.
	view := arguments.BindPlan(&cmd.CommandLine).View
	cmd.Run = func(m command.Meta) int {
		if view.ViewType == arguments.ViewJSON {
			fmt.Fprintln(stderr, "Error: drift has no -json output. For machine-readable drift, run conn3x plan -refresh-only -json.")
			return 1
		}
		// -chdir has already moved conn3x; the plan starts where conn3x did
		// and applies the same -chdir itself.
		return runDrift(os.Args[1:], m.WorkingDir.OriginalWorkingDir(), stdout, stderr)
	}
	return cmd
}

// driftPlanArgs turns the drift command line into its refresh-only plan.
func driftPlanArgs(args []string) []string {
	out := make([]string, 0, len(args)+3)
	for i, a := range args {
		if a == "drift" {
			out = append(out, "plan", "-refresh-only", "-detailed-exitcode", "-json")
			return append(out, args[i+1:]...)
		}
		out = append(out, a)
	}
	return out
}

// driftPlan is the refresh-only plan, run from dir with the drift arguments.
func driftPlan(self, dir string, args []string) *exec.Cmd {
	plan := exec.Command(self, driftPlanArgs(args)...)
	plan.Dir = dir
	return plan
}

// driftConfirmPlan is the normal plan that says which drifted cloud resources
// the config would change back.
func driftConfirmPlan(self, dir string, args []string) *exec.Cmd {
	planArgs := driftPlanArgs(args)
	planArgs = slices.DeleteFunc(planArgs, func(a string) bool {
		return a == "-refresh-only" || a == "-detailed-exitcode"
	})
	plan := exec.Command(self, planArgs...)
	plan.Dir = dir
	return plan
}

// runPlan runs a plan and collects its JSON stream.
func runPlan(plan *exec.Cmd, errOut io.Writer) (driftReport, int, error) {
	plan.Stderr = errOut
	pipe, err := plan.StdoutPipe()
	if err == nil {
		err = plan.Start()
	}
	if err != nil {
		return driftReport{}, 1, fmt.Errorf("running the plan: %w", err)
	}
	r, readErr := readDrift(pipe)
	code := 0
	if err := plan.Wait(); err != nil {
		code = 1
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		}
	}
	if readErr != nil {
		return r, 1, fmt.Errorf("reading the plan: %w", readErr)
	}
	return r, code, nil
}

func runDrift(args []string, dir string, out, errOut io.Writer) int {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(errOut, "Error: finding the conn3x binary: %s\n", err)
		return 1
	}
	r, planCode, err := runPlan(driftPlan(self, dir, args), errOut)
	if err != nil {
		fmt.Fprintf(errOut, "Error: %s\n", err)
		return 1
	}
	if len(r.changedCloud) > 0 && planCode != 1 && len(r.errors) == 0 {
		confirm, confirmCode, err := runPlan(driftConfirmPlan(self, dir, args), errOut)
		if err != nil {
			fmt.Fprintf(errOut, "Error: %s\n", err)
			return 1
		}
		if confirmCode == 1 || len(confirm.errors) > 0 {
			r.errors = append(r.errors, confirm.errors...)
			return reportDrift(r, 1, out)
		}
		r, planCode = r.confirmed(confirm.planned, planCode)
	}
	return reportDrift(r, planCode, out)
}

// reportDrift writes the report for a finished plan and returns the exit code.
func reportDrift(r driftReport, planCode int, out io.Writer) int {
	code := driftExit(r, planCode)
	if code == 1 && len(r.errors) == 0 {
		return 1 // the plan failed before reporting; it said why on stderr
	}
	// plan -detailed-exitcode also exits 2 when only outputs changed.
	r.outputsOnly = planCode == 2 && len(r.cloud)+len(r.hosts) == 0 && len(r.errors) == 0
	r.write(out)
	return code
}

// driftExit is 0 for no drift, 2 for drift and 1 for errors.
func driftExit(r driftReport, planCode int) int {
	switch {
	case len(r.errors) > 0 || planCode == 1:
		return 1
	case len(r.cloud)+len(r.hosts) > 0 || planCode == 2:
		return 2
	}
	return 0
}

type driftReport struct {
	cloud, hosts, errors []string
	outputsOnly          bool
	// changedCloud holds the addresses in cloud reported as changed rather
	// than gone; notes holds those the config wouldn't change back.
	changedCloud []string
	notes        []string
	// planned holds the addresses a normal plan would change.
	planned []string
}

// confirmed moves the changed cloud resources a normal plan leaves alone from
// drift to notes.
//
// shortcut: planCode goes to 0 when nothing is left, which also hides an output
// that changed alongside; upgrade if someone alerts on outputs alone.
func (r driftReport) confirmed(planned []string, planCode int) (driftReport, int) {
	var kept []string
	for _, line := range r.cloud {
		addr := strings.TrimSuffix(strings.TrimPrefix(line, "  ~ "), "  changed")
		if !slices.Contains(r.changedCloud, addr) || slices.Contains(planned, addr) {
			kept = append(kept, line)
			continue
		}
		r.notes = append(r.notes, "  "+addr)
	}
	r.cloud = kept
	if len(r.cloud)+len(r.hosts) == 0 {
		planCode = 0
	}
	return r, planCode
}

// readDrift collects the drifted resources and errors from plan -json.
func readDrift(r io.Reader) (driftReport, error) {
	var rep driftReport
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var msg struct {
			Type   string `json:"type"`
			Change struct {
				Resource struct {
					Addr string `json:"addr"`
					Type string `json:"resource_type"`
				} `json:"resource"`
				Action string `json:"action"`
			} `json:"change"`
			Diagnostic struct {
				Severity, Summary, Detail string
			} `json:"diagnostic"`
		}
		if json.Unmarshal(sc.Bytes(), &msg) != nil {
			continue
		}
		switch msg.Type {
		case "resource_drift":
			line := "  ~ " + msg.Change.Resource.Addr + "  changed"
			if msg.Change.Action == "delete" {
				line = "  - " + msg.Change.Resource.Addr + "  gone"
			}
			if strings.HasPrefix(msg.Change.Resource.Type, "conn3x_") {
				rep.hosts = append(rep.hosts, line)
			} else {
				rep.cloud = append(rep.cloud, line)
				if msg.Change.Action != "delete" {
					rep.changedCloud = append(rep.changedCloud, msg.Change.Resource.Addr)
				}
			}
		case "planned_change":
			if slices.Contains([]string{"update", "replace", "delete"}, msg.Change.Action) {
				rep.planned = append(rep.planned, msg.Change.Resource.Addr)
			}
		case "diagnostic":
			// A host the refresh couldn't reach is only a warning to plan,
			// but drift can't report it as unchanged.
			if msg.Diagnostic.Severity == "error" || msg.Diagnostic.Summary == provider.UnreachableSummary {
				e := "Error: " + msg.Diagnostic.Summary
				if msg.Diagnostic.Detail != "" {
					e += "\n  " + strings.ReplaceAll(msg.Diagnostic.Detail, "\n", "\n  ")
				}
				// Every step on a host that's down says the same thing.
				if !slices.Contains(rep.errors, e) {
					rep.errors = append(rep.errors, e)
				}
			}
		}
	}
	return rep, sc.Err()
}

func (r driftReport) write(w io.Writer) {
	n := len(r.cloud) + len(r.hosts)
	switch {
	case r.outputsOnly:
		fmt.Fprintln(w, "Only outputs changed since the last apply; the cloud and the hosts match it.")
		return
	case n == 0 && len(r.errors) == 0:
		fmt.Fprintln(w, "No drift: the cloud and the hosts match the last apply.")
		r.writeNotes(w)
		return
	case n == 1:
		fmt.Fprintln(w, "Drift found in 1 resource.")
	case n > 1:
		fmt.Fprintf(w, "Drift found in %d resources.\n", n)
	}
	for _, layer := range []struct {
		name  string
		lines []string
	}{{"Cloud", r.cloud}, {"Hosts", r.hosts}} {
		if len(layer.lines) > 0 {
			fmt.Fprintf(w, "\n%s\n%s\n", layer.name, strings.Join(layer.lines, "\n"))
		}
	}
	for _, e := range r.errors {
		fmt.Fprintf(w, "\n%s\n", e)
	}
	if n > 0 {
		fmt.Fprintln(w, "\nRun conn3x plan to see what Conn3x would change to put them back.")
	}
	r.writeNotes(w)
}

func (r driftReport) writeNotes(w io.Writer) {
	if len(r.notes) > 0 {
		fmt.Fprintf(w, "\nChanged, but your config wouldn't change them back\n%s\n", strings.Join(r.notes, "\n"))
	}
}
