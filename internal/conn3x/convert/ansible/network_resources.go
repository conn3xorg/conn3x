// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"
)

// Ansible's network resource modules (eos_vlans, junos_interfaces, ...)
// take a config, one object or a list of them, and a state. Only merged,
// the default, adds what the play names and leaves the rest, as a Conn3x
// step does; replaced does the same for a single object such as the
// hostname. overridden and deleted remove what the play doesn't name, and
// gathered, rendered and parsed don't change the device, so those stay for
// review.
func resourceState(in *input, single bool) string {
	st := in.str("state")
	if st == "" || st == "merged" || (single && st == "replaced") {
		return ""
	}
	return "sets state: " + st + ", which removes or reads configuration the play doesn't name; a Conn3x step only adds what it's given"
}

// resourceItems is config as a list of objects, each as its keys' scalars.
// A value that isn't a scalar is left out, so its key is reported unknown.
func resourceItems(in *input) ([]map[string]*yaml.Node, string) {
	n, ok := in.args["config"]
	if !ok {
		return nil, "sets no config"
	}
	in.used["config"] = true
	var nodes []*yaml.Node
	if n.Kind == yaml.MappingNode {
		nodes = []*yaml.Node{n}
	} else {
		nodes = seq(n)
	}
	var items []map[string]*yaml.Node
	for _, e := range nodes {
		if e.Kind != yaml.MappingNode {
			return nil, "has a config item that isn't an object"
		}
		items = append(items, mapping(e))
	}
	if len(items) == 0 {
		return nil, "sets no config"
	}
	return items, ""
}

// itemValue reads one key of a config item as text, with play variables
// filled in like any other argument.
func itemValue(in *input, item map[string]*yaml.Node, key string) (string, bool) {
	n, ok := item[key]
	if !ok {
		return "", false
	}
	return in.render("config", scalar(n)), true
}

// unknownKeys names an item's keys outside allowed, so a setting the step
// can't express isn't dropped quietly.
func unknownKeys(item map[string]*yaml.Node, allowed ...string) string {
	var extra []string
	for k := range item {
		if !contains(allowed, k) {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	return strings.Join(extra, ", ")
}

func contains(list []string, s string) bool {
	for _, l := range list {
		if l == s {
			return true
		}
	}
	return false
}

var nonName = regexp.MustCompile(`[^A-Za-z0-9]+`)

// itemSuffix tells several steps from one task apart, from what names an
// item: vlan_10, ge_0_0_1.
func itemSuffix(prefix, v string) string {
	return prefix + strings.Trim(nonName.ReplaceAllString(strings.ToLower(v), "_"), "_")
}

// networkHostname converts eos_hostname, junos_hostname and vyos_hostname.
func networkHostname(platform string) func(*input) ([]step, string) {
	return func(in *input) ([]step, string) {
		if reason := resourceState(in, true); reason != "" {
			return nil, reason
		}
		items, reason := resourceItems(in)
		if reason != "" {
			return nil, reason
		}
		if len(items) != 1 {
			return nil, "sets more than one hostname"
		}
		if extra := unknownKeys(items[0], "hostname"); extra != "" {
			return nil, "sets " + extra + " in config, which a " + platform + "_hostname step doesn't take"
		}
		name, ok := itemValue(in, items[0], "hostname")
		if in.problem != "" {
			return nil, in.problem
		}
		if !ok || name == "" {
			return nil, "has no hostname in config"
		}
		return one(platform+"_hostname", []attr{s("name", name)})
	}
}

// networkVLANs converts eos_vlans and junos_vlans, a step per VLAN.
func networkVLANs(platform string) func(*input) ([]step, string) {
	return func(in *input) ([]step, string) {
		if reason := resourceState(in, false); reason != "" {
			return nil, reason
		}
		items, reason := resourceItems(in)
		if reason != "" {
			return nil, reason
		}
		allowed := []string{"vlan_id", "name"}
		if platform == "eos" {
			allowed = append(allowed, "state")
		}
		var steps []step
		for _, item := range items {
			if extra := unknownKeys(item, allowed...); extra != "" {
				return nil, "sets " + extra + " on a VLAN, which a " + platform + "_vlan step doesn't take"
			}
			if st, _ := itemValue(in, item, "state"); st != "" && st != "active" {
				return nil, "sets a VLAN's state to " + st + ", which an eos_vlan step doesn't take"
			}
			idText, hasID := itemValue(in, item, "vlan_id")
			name, _ := itemValue(in, item, "name")
			if in.problem != "" {
				return nil, in.problem
			}
			id, err := strconv.Atoi(idText)
			if !hasID || err != nil || id < 1 || id > 4094 {
				return nil, fmt.Sprintf("has a VLAN without a vlan_id from 1 to 4094 (%q), which a %s_vlan step needs", idText, platform)
			}
			attrs := []attr{{key: "vlan_id", val: cty.NumberIntVal(int64(id))}}
			if platform == "junos" {
				if name == "" {
					return nil, "has a VLAN without a name, which a junos_vlan step needs"
				}
				attrs = []attr{s("name", name), attrs[0]}
			} else if name != "" {
				attrs = append(attrs, s("name", name))
			}
			steps = append(steps, step{module: platform + "_vlan", attrs: attrs, suffix: itemSuffix("vlan_", idText)})
		}
		return steps, ""
	}
}

// networkInterfaces converts eos_interfaces, junos_interfaces and
// vyos_interfaces: name, description, mtu and enabled. Junos and VyOS
// default enabled to true, so an item without it still enables the
// interface, and the step says so.
func networkInterfaces(platform string) func(*input) ([]step, string) {
	return func(in *input) ([]step, string) {
		if reason := resourceState(in, false); reason != "" {
			return nil, reason
		}
		items, reason := resourceItems(in)
		if reason != "" {
			return nil, reason
		}
		var steps []step
		for _, item := range items {
			allowed := []string{"name", "description", "mtu", "enabled"}
			if platform == "vyos" {
				// vyos_interfaces also takes enable.
				allowed = append(allowed, "enable")
				if _, ok := item["enabled"]; !ok && item["enable"] != nil {
					item["enabled"] = item["enable"]
				}
			}
			if extra := unknownKeys(item, allowed...); extra != "" {
				return nil, "sets " + extra + " on an interface, which a " + platform + "_interface step doesn't take"
			}
			name, _ := itemValue(in, item, "name")
			if name == "" {
				return nil, "has an interface without a name"
			}
			attrs := []attr{s("name", name)}
			if d, ok := itemValue(in, item, "description"); ok {
				attrs = append(attrs, s("description", d))
			}
			if e, ok := itemValue(in, item, "enabled"); ok {
				attrs = append(attrs, attr{key: "enabled", val: cty.BoolVal(truthy(e))})
			} else if platform != "eos" {
				attrs = append(attrs, attr{key: "enabled", val: cty.True})
			}
			if m, ok := itemValue(in, item, "mtu"); ok {
				n, err := strconv.Atoi(m)
				if err != nil || n < 1 {
					return nil, fmt.Sprintf("sets mtu %q on %s, which isn't a whole number", m, name)
				}
				attrs = append(attrs, attr{key: "mtu", val: cty.NumberIntVal(int64(n))})
			}
			if in.problem != "" {
				return nil, in.problem
			}
			steps = append(steps, step{module: platform + "_interface", attrs: attrs, suffix: itemSuffix("", name)})
		}
		return steps, ""
	}
}

// vyosL3Interfaces converts vyos_l3_interfaces into vyos_interface's
// addresses, a step per interface. Sub-interfaces (vifs) stay for review.
func vyosL3Interfaces(in *input) ([]step, string) {
	if reason := resourceState(in, false); reason != "" {
		return nil, reason
	}
	items, reason := resourceItems(in)
	if reason != "" {
		return nil, reason
	}
	var steps []step
	for _, item := range items {
		if extra := unknownKeys(item, "name", "ipv4", "ipv6"); extra != "" {
			return nil, "sets " + extra + " on an interface, which a vyos_interface step doesn't take"
		}
		name, _ := itemValue(in, item, "name")
		if name == "" {
			return nil, "has an interface without a name"
		}
		var addrs []string
		for _, fam := range []string{"ipv4", "ipv6"} {
			for _, a := range seq(item[fam]) {
				m := mapping(a)
				if extra := unknownKeys(m, "address"); extra != "" {
					return nil, "sets " + extra + " on an " + fam + " address of " + name + ", which a vyos_interface step doesn't take"
				}
				if v, ok := itemValue(in, m, "address"); ok && v != "" {
					addrs = append(addrs, v)
				}
			}
		}
		if in.problem != "" {
			return nil, in.problem
		}
		if len(addrs) == 0 {
			return nil, "sets no address on " + name
		}
		steps = append(steps, step{module: "vyos_interface", attrs: []attr{s("name", name), {key: "addresses", val: strList(addrs)}}, suffix: itemSuffix("", name)})
	}
	return steps, ""
}
