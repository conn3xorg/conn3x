// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/command/arguments"
	runreport "github.com/opentofu/opentofu/internal/conn3x/report"
)

const reportFlagHelp = "Write a JSON report of the run to this file: each host's steps and what happened to them, and the errors as printed. See the run report reference for the format."

// withReport gives apply a -report flag. The apply runs as before, with its
// -json stream also sent to a temporary file through -json-into (or to the
// caller's own -json-into file), and the report is built from that stream.
func withReport(cmd *command.Command) {
	var path string
	cmd.CommandLine.StringVar(&path, "report", "", reportFlagHelp).SetDisplay("=run.json")
	view := cmd.CommandLine.View
	run := cmd.Run
	cmd.Run = func(m command.Meta) int {
		if path == "" {
			return run(m)
		}
		if view.ViewType == arguments.ViewJSON {
			fmt.Fprintln(stderr, "Error: -report doesn't go with -json, whose stream on standard output already has everything; use -json-into to keep the human output")
			return 1
		}
		var stream string
		if view.JSONInto != nil {
			stream = view.JSONInto.Name()
		} else {
			tmp, err := os.CreateTemp("", "conn3x-report-*.json")
			if err != nil {
				fmt.Fprintf(stderr, "Error: making a file for the report's stream: %s\n", err)
				return 1
			}
			defer os.Remove(tmp.Name())
			defer tmp.Close()
			view.JSONInto, stream = tmp, tmp.Name()
		}
		started := time.Now()
		code := run(m)
		if err := writeApplyReport(path, stream, started, code == 0); err != nil {
			fmt.Fprintf(stderr, "Error: writing the report: %s\n", err)
			if code == 0 {
				code = 1
			}
		}
		return code
	}
}

func writeApplyReport(path, stream string, started time.Time, success bool) error {
	in, err := os.Open(stream)
	if err != nil {
		return err
	}
	defer in.Close()
	r := runreport.New("apply", started)
	if err := r.FromApply(in, success); err != nil {
		return err
	}
	return writeReport(path, r)
}

// writeReport writes r to path, readable by its owner only: its errors can
// carry what a failed command printed, and reports get copied about.
func writeReport(path string, r *runreport.Report) error {
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := r.Write(out, time.Now()); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// withoutReport takes -report and its value out of a command line, for the
// plan drift runs, which doesn't take it.
func withoutReport(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-report" || a == "--report":
			i++ // and its value
		case strings.HasPrefix(a, "-report=") || strings.HasPrefix(a, "--report="):
		default:
			out = append(out, a)
		}
	}
	return out
}

// driftToReport fills a drift report from what drift found.
func driftToReport(r driftReport, code int, started time.Time) *runreport.Report {
	rep := runreport.New("drift", started)
	rep.Success = code != 1
	for _, line := range append(append([]string{}, r.hosts...), r.cloud...) {
		gone := strings.HasSuffix(line, "  gone")
		addr := strings.TrimSpace(line)
		addr = strings.TrimPrefix(strings.TrimPrefix(addr, "~ "), "- ")
		addr = strings.TrimSuffix(strings.TrimSuffix(addr, "  changed"), "  gone")
		rep.AddDrift(addr, gone)
	}
	rep.Errors = append(rep.Errors, r.errors...)
	return rep
}
