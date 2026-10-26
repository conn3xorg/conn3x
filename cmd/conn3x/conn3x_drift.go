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
	"strings"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/command/arguments"
	"github.com/opentofu/opentofu/internal/conn3x/provider"
)

// driftCommand reports what changed outside Conn3x since the last apply,
// split into the cloud resources and the host steps. It runs a refresh-only
// plan and exits 2 when anything drifted, like plan -detailed-exitcode.
func driftCommand() command.Command {
	cmd := command.Command{
		Name:  "drift",
		Short: "Report what changed outside Conn3x, in the cloud and on hosts",
		Long: `Reads every resource and host step again and reports what no longer matches the last apply, grouped into cloud resources and host steps. Nothing is changed.

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

func runDrift(args []string, dir string, out, errOut io.Writer) int {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(errOut, "Error: finding the conn3x binary: %s\n", err)
		return 1
	}
	plan := driftPlan(self, dir, args)
	plan.Stderr = errOut
	pipe, err := plan.StdoutPipe()
	if err == nil {
		err = plan.Start()
	}
	if err != nil {
		fmt.Fprintf(errOut, "Error: running the refresh-only plan: %s\n", err)
		return 1
	}
	r, readErr := readDrift(pipe)
	planCode := 0
	if err := plan.Wait(); err != nil {
		planCode = 1
		if exit, ok := err.(*exec.ExitError); ok {
			planCode = exit.ExitCode()
		}
	}
	if readErr != nil {
		fmt.Fprintf(errOut, "Error: reading the plan: %s\n", readErr)
		return 1
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
			}
		case "diagnostic":
			// A host the refresh couldn't reach is only a warning to plan,
			// but drift can't report it as unchanged.
			if msg.Diagnostic.Severity == "error" || msg.Diagnostic.Summary == provider.UnreachableSummary {
				e := "Error: " + msg.Diagnostic.Summary
				if msg.Diagnostic.Detail != "" {
					e += "\n  " + strings.ReplaceAll(msg.Diagnostic.Detail, "\n", "\n  ")
				}
				rep.errors = append(rep.errors, e)
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
}
