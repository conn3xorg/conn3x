// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// networkModules are the network device modules the converter translates,
// by platform. A play made only of these can take connection: network_cli.
var networkModules = map[string]string{
	"ios_config":   "ios",
	"eos_config":   "eos",
	"junos_config": "junos",
	"vyos_config":  "vyos",

	"eos_hostname": "eos", "junos_hostname": "junos", "vyos_hostname": "vyos",
	"eos_vlans": "eos", "junos_vlans": "junos",
	"eos_interfaces": "eos", "junos_interfaces": "junos", "vyos_interfaces": "vyos",
	"vyos_l3_interfaces": "vyos",
}

// networkConfig converts ios_config, eos_config, junos_config and
// vyos_config. Their defaults (match: line, replace: line, Junos update:
// merge) are what the Conn3x step does, so they go quietly; anything that
// changes what's compared stays for review.
func networkConfig(platform string) func(*input) ([]step, string) {
	return func(in *input) ([]step, string) {
		key := "lines"
		if !in.has(key) {
			key = "commands"
		}
		if !in.has(key) {
			if in.has("src") {
				return nil, "sets src, a configuration file to compare as a whole, which a " + platform + "_config step doesn't take; copy its lines into lines"
			}
			return nil, "sets no lines"
		}
		for _, e := range seq(in.args[key]) {
			if e.Kind != yaml.ScalarNode {
				return nil, key + " has a line with prompt and answer, which a " + platform + "_config step can't type in; set the answer as a line of its own"
			}
		}
		lines := in.list(key)
		if in.problem != "" {
			return nil, in.problem
		}
		if len(lines) == 0 {
			return nil, "sets no lines"
		}
		for _, l := range lines {
			if strings.Contains(l, "\x00") {
				return nil, key + " is built from a loop, which a " + platform + "_config step takes as one list; write the lines out"
			}
			if (platform == "junos" || platform == "vyos") && !strings.HasPrefix(l, "set ") {
				return nil, fmt.Sprintf("has the line %q, and a %s_config step takes only set lines; remove it by hand, or take the step out with on_remove", l, platform)
			}
		}
		if m := in.str("match"); m != "" && m != "line" {
			return nil, fmt.Sprintf("sets match: %s, which compares differently from a %s_config step's lines", m, platform)
		}
		// replace: block re-sends a whole block when one line differs but
		// leaves extra lines alone, which isn't the step's match = "block".
		if r := in.str("replace"); r != "" && r != "line" {
			return nil, fmt.Sprintf("sets replace: %s, which a %s_config step doesn't do: it sends only the lines that are missing", r, platform)
		}
		if u := in.str("update"); u != "" && u != "merge" {
			return nil, fmt.Sprintf("sets update: %s, and a junos_config step only merges its lines in", u)
		}
		if in.has("src") {
			return nil, "sets src as well as " + key + ", which a " + platform + "_config step can't combine"
		}
		attrs := []attr{}
		if platform == "ios" || platform == "eos" {
			if parents := in.list("parents"); len(parents) > 0 {
				attrs = append(attrs, attr{key: "parents", val: strList(parents)})
			}
		}
		attrs = append(attrs, attr{key: "lines", val: strList(lines)})
		var notes []string
		for _, k := range []string{"save_when", "save"} {
			if in.has(k) {
				in.ignore(k)
				saved := "Conn3x saves the running configuration after every change"
				if platform == "junos" {
					saved = "a Junos commit persists by itself"
				}
				notes = append(notes, k+" dropped: "+saved+".")
			}
		}
		if in.has("confirm") {
			in.ignore("confirm")
			notes = append(notes, "confirm dropped: every change goes in under a revert timer, and Conn3x confirms it after logging in again.")
		}
		if in.has("backup") {
			in.ignore("backup", "backup_options")
			notes = append(notes, "backup dropped: set device_backup_dir on the circuit to keep a copy of the configuration before each change.")
		}
		return one(platform+"_config", attrs, notes...)
	}
}

// networkPlatforms is the set of platforms a play's tasks configure, and
// whether every task in it is a network module the converter translates.
// A play with roles, or with any other task, isn't all network.
func networkPlatforms(p map[string]*yaml.Node) (map[string]bool, bool) {
	if p["roles"] != nil {
		return nil, false
	}
	found := map[string]bool{}
	all := true
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		for _, t := range seq(n) {
			task := mapping(t)
			if b := task["block"]; b != nil {
				walk(b)
				walk(task["rescue"])
				walk(task["always"])
				continue
			}
			mod, _ := moduleOf(task)
			if platform, ok := networkModules[mod]; ok {
				found[platform] = true
			} else {
				all = false
			}
		}
	}
	for _, k := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
		walk(p[k])
	}
	return found, all && len(found) > 0
}
