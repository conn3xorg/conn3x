// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/command/arguments"
	"github.com/opentofu/opentofu/internal/configs"
	"github.com/opentofu/opentofu/internal/tofu"
)

// brLimited is an apply with withLimit, parsed from args, whose own run
// records the limit and rescue hosts it saw.
func brLimited(args ...string) (cmd command.Command, saw *[]string) {
	var plan string
	saw = new([]string)
	cmd = command.Command{Name: "apply", CommandLine: arguments.CommandLine{View: &arguments.View{}, Operation: &arguments.Operation{}}}
	cmd.CommandLine.PositionalArg(&plan, "PLAN", true)
	cmd.Run = func(command.Meta) int {
		limit := ""
		if tofu.Conn3xCLILimit != nil {
			limit = "limited"
		}
		*saw = append(*saw, limit, tofu.Conn3xCLILimitCircuit, strings.Join(configs.Conn3xRescueHosts["web__undo"], ","))
		return 42
	}
	withLimit(&cmd)
	cmd.CommandLine.ParseLegacy(args)
	return cmd, saw
}

// -limit reaches the plan for the run alone, narrowed to a batch's circuit
// when a batched apply says so, and a bad one never runs.
func TestWithLimit(t *testing.T) {
	var errOut bytes.Buffer
	old := stderr
	stderr = &errOut
	t.Cleanup(func() { stderr = old })
	t.Chdir(t.TempDir())

	cmd, saw := brLimited()
	if code := cmd.Run(command.Meta{}); code != 42 || strings.Join(*saw, "|") != "||" {
		t.Errorf("no -limit: exit %d, saw %q", code, *saw)
	}
	t.Setenv(batchCircuitEnv, "web")
	cmd, saw = brLimited("-limit=web*")
	if code := cmd.Run(command.Meta{}); code != 42 || strings.Join(*saw, "|") != "limited|web|" {
		t.Errorf("-limit: exit %d, saw %q", code, *saw)
	}
	if tofu.Conn3xCLILimit != nil || tofu.Conn3xCLILimitCircuit != "" {
		t.Error("the limit outlived the run")
	}
	for args, want := range map[string]string{
		"-limit=~(":          "Error: -limit=~(:",
		"-limit=web1 tfplan": "a saved plan can't be limited",
	} {
		errOut.Reset()
		cmd, saw := brLimited(strings.Fields(args)...)
		if code := cmd.Run(command.Meta{}); code != 1 || !strings.Contains(errOut.String(), want) || len(*saw) != 0 {
			t.Errorf("%s: exit %d, %q", args, code, errOut.String())
		}
	}

	// A batched apply's rescue phase hands its hosts over in the
	// environment, for this run alone.
	t.Setenv(rescueHostsEnv, `{"web__undo": ["web1", "web2"]}`)
	cmd, saw = brLimited()
	if code := cmd.Run(command.Meta{}); code != 42 || (*saw)[2] != "web1,web2" || configs.Conn3xRescueHosts != nil {
		t.Errorf("rescue hosts: exit %d, saw %q, left %v", code, *saw, configs.Conn3xRescueHosts)
	}
	errOut.Reset()
	t.Setenv(rescueHostsEnv, "not json")
	cmd, saw = brLimited()
	if code := cmd.Run(command.Meta{}); code != 1 || !strings.Contains(errOut.String(), rescueHostsEnv) || len(*saw) != 0 {
		t.Errorf("bad rescue hosts: exit %d, %q", code, errOut.String())
	}
}
