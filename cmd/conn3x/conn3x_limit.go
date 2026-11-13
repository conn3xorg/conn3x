// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	cli "github.com/urfave/cli/v3"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/configs"
	"github.com/opentofu/opentofu/internal/conn3x/hostpattern"
	"github.com/opentofu/opentofu/internal/tofu"
)

const limitFlagHelp = `Run circuit steps only on the hosts that match, as with Ansible's --limit: host names and globs split by "," or ":", "!" in front to leave hosts out, "&" to narrow, "~" for a regular expression. Other hosts' steps are left as they are. Cannot be used with -target or -exclude.`

// withLimit gives plan, apply or refresh a -limit flag, which it hands to
// the plan (see internal/tofu/conn3x_limit.go).
func withLimit(cmd *command.Command) {
	var raw string
	cmd.CommandLine.StringVar(&raw, "limit", "", limitFlagHelp).SetDisplay("=hosts")
	var planPath *string // apply's PLAN argument
	for _, a := range cmd.CommandLine.Args {
		if s, ok := a.Cli.(*cli.StringArg); ok && a.Name == "PLAN" {
			planPath = s.Destination
		}
	}
	run := cmd.Run
	cmd.Run = func(m command.Meta) int {
		// Set only by apply, for its own rescue plans and their applies.
		if v := os.Getenv(rescueHostsEnv); v != "" {
			if err := json.Unmarshal([]byte(v), &configs.Conn3xRescueHosts); err != nil {
				fmt.Fprintf(stderr, "Error: %s: %s\n", rescueHostsEnv, err)
				return 1
			}
			defer func() { configs.Conn3xRescueHosts = nil }()
		}
		if raw == "" {
			return run(m)
		}
		limit, err := hostpattern.Parse(raw)
		if err == nil {
			err = limitReachesPlan(m, planPath)
		}
		if err != nil {
			fmt.Fprintf(stderr, "Error: -limit=%s: %s\n", raw, err)
			return 1
		}
		tofu.Conn3xCLILimit = limit
		// Set only by a batched apply, for its own plans.
		tofu.Conn3xCLILimitCircuit = os.Getenv(batchCircuitEnv)
		defer func() { tofu.Conn3xCLILimit, tofu.Conn3xCLILimitCircuit = nil, "" }()
		return run(m)
	}
}

// limitReachesPlan refuses a -limit that the plan wouldn't see: on applying
// a saved plan, which was limited or not when made, or with a remote or
// cloud backend, which plans elsewhere.
func limitReachesPlan(m command.Meta, planPath *string) error {
	if planPath != nil && *planPath != "" {
		return fmt.Errorf("a saved plan can't be limited when applied; give -limit to the plan instead")
	}
	dataDir := ".terraform"
	if m.WorkingDir != nil {
		dataDir = m.WorkingDir.DataDir()
	}
	b, err := os.ReadFile(filepath.Join(dataDir, "terraform.tfstate"))
	if err != nil {
		return nil // not initialized, or the local backend
	}
	var st struct {
		Backend struct{ Type string } `json:"backend"`
	}
	if json.Unmarshal(b, &st) == nil && (st.Backend.Type == "remote" || st.Backend.Type == "cloud") {
		return fmt.Errorf("the %s backend plans remotely, where -limit doesn't reach", st.Backend.Type)
	}
	return nil
}
