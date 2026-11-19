// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/opentofu/opentofu/internal/conn3x/termsafe"
)

// listHostsOf prints what -list-hosts shows, as ansible --list-hosts does:
// a count, then one name per line. No match is a count of 0, not an error,
// since checking a pattern is the point.
func (o runOptions) listHostsOf(stdout io.Writer, hosts []*runHost) int {
	if o.json {
		line, _ := json.Marshal(hostNames(hosts))
		fmt.Fprintln(stdout, string(line))
		return 0
	}
	fmt.Fprintf(stdout, "  hosts (%d):\n", len(hosts))
	for _, h := range hosts {
		fmt.Fprintln(stdout, "    "+termsafe.Escape(h.name))
	}
	return 0
}

// listPlanHosts is -list-hosts with -plan: each run's hosts under its name.
func (o runOptions) listPlanHosts(stdout io.Writer, steps []planStep) int {
	if o.json {
		type run struct {
			Run   string   `json:"run"`
			Hosts []string `json:"hosts"`
		}
		var runs []run
		for _, s := range steps {
			runs = append(runs, run{s.run.name, hostNames(s.hosts)})
		}
		line, _ := json.Marshal(runs)
		fmt.Fprintln(stdout, string(line))
		return 0
	}
	for _, s := range steps {
		fmt.Fprintln(stdout, termsafe.Escape(fmt.Sprintf("run %s, task %s:", s.run.name, s.run.task.name)))
		o.listHostsOf(stdout, s.hosts)
	}
	return 0
}

func hostNames(hosts []*runHost) []string {
	names := []string{}
	for _, h := range hosts {
		names = append(names, h.name)
	}
	return names
}
