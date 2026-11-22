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

	"github.com/opentofu/opentofu/internal/conn3x/modules/eos"
	"github.com/opentofu/opentofu/internal/conn3x/modules/ios"
	"github.com/opentofu/opentofu/internal/conn3x/modules/junos"
	"github.com/opentofu/opentofu/internal/conn3x/modules/vyos"
)

// Ansible's network resource modules (eos_vlans, junos_interfaces, ...)
// take a config, one object or a list of them, and a state. merged, the
// default, adds what the play names and leaves the rest, as a Conn3x step
// does for one value or a whole object it creates, but not for a list the
// step owns as a set (see addsToLists). replaced does the same for a single
// object such as the hostname, and sets each named object's lists whole. overridden and deleted remove what the play doesn't name, and
// gathered, rendered and parsed don't change the device, so those stay for
// review.
func resourceState(in *input, single bool) string {
	st := in.str("state")
	if st == "" || st == "merged" || (single && st == "replaced") {
		return ""
	}
	return "sets state: " + st + ", which removes or reads configuration the play doesn't name; a Conn3x step only adds what it's given"
}

// addsToLists reports whether a task merges, which adds a list's items to
// what the device has. A step's list, such as a route's next_hops, is all
// of them, so a merged list would delete the rest; replaced sets the whole
// list for each object it names, as the step does.
func addsToLists(in *input) bool {
	st := in.str("state")
	return st == "" || st == "merged"
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
		// A name from a variable is checked when the circuit is validated.
		if !strings.Contains(name, "${") {
			if err := hostnameRules[platform](name); err != nil {
				return nil, "sets a hostname the " + platform + "_hostname step refuses: " + err.Error()
			}
		}
		return one(platform+"_hostname", []attr{s("name", name)})
	}
}

// hostnameRules are each platform's hostname step's own check, so a name
// the step would refuse stays for review instead of failing validate.
var hostnameRules = map[string]func(string) error{
	"eos":   eos.ValidateHostname,
	"ios":   ios.ValidateHostname,
	"junos": junos.ValidateHostname,
	"vyos":  vyos.ValidateHostname,
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
			} else if platform != "eos" && platform != "ios" {
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
			if platform == "ios" && !strings.Contains(name, "${") {
				// Ansible expands a short name such as Gi1/0/1; the step
				// takes the name as show running-config prints it.
				if err := (ios.Interface{Name: name}).Validate(); err != nil {
					return nil, err.Error()
				}
			}
			steps = append(steps, step{module: platform + "_interface", attrs: attrs, suffix: itemSuffix("", name)})
		}
		return steps, ""
	}
}

// iosL2Interfaces converts ios_l2_interfaces into ios_interface's switchport
// settings, a step per interface: mode access or trunk and access.vlan. A
// trunk's allowed_vlans stays for review, since merged adds to the list and
// the step owns all of it; so do a native VLAN, an encapsulation, a voice
// VLAN and the other switchport settings.
func iosL2Interfaces(in *input) ([]step, string) {
	if reason := resourceState(in, false); reason != "" {
		return nil, reason
	}
	items, reason := resourceItems(in)
	if reason != "" {
		return nil, reason
	}
	var steps []step
	for _, item := range items {
		if extra := unknownKeys(item, "name", "mode", "access", "trunk"); extra != "" {
			return nil, "sets " + extra + " on an interface, which an ios_interface step doesn't take"
		}
		name, _ := itemValue(in, item, "name")
		if name == "" {
			return nil, "has an interface without a name"
		}
		want := ios.Interface{Name: name}
		attrs := []attr{s("name", name)}
		if m, ok := itemValue(in, item, "mode"); ok {
			if m != "access" && m != "trunk" {
				return nil, fmt.Sprintf("sets mode %s on %s; an ios_interface step takes access or trunk", m, name)
			}
			want.Mode = m
			attrs = append(attrs, s("mode", m))
		}
		if a := item["access"]; a != nil {
			access := mapping(a)
			if extra := unknownKeys(access, "vlan"); extra != "" {
				return nil, "sets access " + extra + " on " + name + ", which an ios_interface step doesn't take"
			}
			v, _ := itemValue(in, access, "vlan")
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Sprintf("sets access vlan %q on %s, which isn't a VLAN number", v, name)
			}
			want.AccessVLAN = n
			attrs = append(attrs, attr{key: "access_vlan", val: cty.NumberIntVal(int64(n))})
		}
		if t := item["trunk"]; t != nil {
			trunk := mapping(t)
			if trunk["allowed_vlans"] != nil {
				// merged adds these to what the trunk carries, and the step's
				// allowed_vlans is the whole list: converted, a play that adds
				// VLANs would remove the rest.
				return nil, "sets trunk allowed_vlans on " + name + ", which adds them to the trunk's list; an ios_interface step's allowed_vlans is the whole list, so write every VLAN the trunk should carry"
			}
			if extra := unknownKeys(trunk); extra != "" {
				return nil, "sets trunk " + extra + " on " + name + ", which an ios_interface step doesn't take"
			}
		}
		if in.problem != "" {
			return nil, in.problem
		}
		if len(attrs) == 1 {
			return nil, "sets nothing on " + name + " that an ios_interface step takes"
		}
		if !strings.Contains(name, "${") {
			if err := want.Validate(); err != nil {
				return nil, err.Error()
			}
		}
		steps = append(steps, step{module: "ios_interface", attrs: attrs, suffix: itemSuffix("", name)})
	}
	return steps, ""
}

// vyosL3Interfaces converts vyos_l3_interfaces into vyos_interface's
// addresses, a step per interface. Sub-interfaces (vifs) stay for review.
func vyosL3Interfaces(in *input) ([]step, string) {
	if reason := resourceState(in, true); reason != "" {
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
		if addsToLists(in) {
			return nil, "sets addresses on " + name + " under state: merged, which adds them to the ones it has; a vyos_interface step's addresses are all of them, so write every address " + name + " should have, or use state: replaced"
		}
		steps = append(steps, step{module: "vyos_interface", attrs: []attr{s("name", name), {key: "addresses", val: strList(addrs)}}, suffix: itemSuffix("", name)})
	}
	return steps, ""
}

// networkStaticRoutes converts junos_static_routes and vyos_static_routes:
// a step per destination, its next hops' forward_router_address as
// next_hops. IPv6, a VRF, an interface or blackhole next hop, and a Junos
// metric (not the step's preference, which is Junos's route preference)
// stay for review.
func networkStaticRoutes(platform string) func(*input) ([]step, string) {
	return func(in *input) ([]step, string) {
		if reason := resourceState(in, true); reason != "" {
			return nil, reason
		}
		items, reason := resourceItems(in)
		if reason != "" {
			return nil, reason
		}
		hopKey, hopKeys := "next_hop", []string{"forward_router_address"}
		routeKeys := []string{"dest", "next_hop", "metric"}
		if platform == "vyos" {
			hopKey, hopKeys = "next_hops", []string{"forward_router_address", "admin_distance"}
			routeKeys = []string{"dest", "next_hops"}
		}
		var steps []step
		for _, item := range items {
			if extra := unknownKeys(item, "address_families"); extra != "" {
				return nil, "sets " + extra + " on a route set, which a " + platform + "_static_route step doesn't take"
			}
			for _, fam := range seq(item["address_families"]) {
				f := mapping(fam)
				if afi, _ := itemValue(in, f, "afi"); afi != "ipv4" {
					return nil, fmt.Sprintf("sets afi %q, and a %s_static_route step takes IPv4 routes only", afi, platform)
				}
				for _, r := range seq(f["routes"]) {
					route := mapping(r)
					if extra := unknownKeys(route, routeKeys...); extra != "" {
						return nil, "sets " + extra + " on a route, which a " + platform + "_static_route step doesn't take"
					}
					if _, ok := route["metric"]; ok {
						return nil, "sets metric on a route, which Junos keeps apart from the preference a junos_static_route step sets"
					}
					dest, _ := itemValue(in, route, "dest")
					var hops []string
					distance := ""
					for i, h := range seq(route[hopKey]) {
						hop := mapping(h)
						if extra := unknownKeys(hop, hopKeys...); extra != "" {
							return nil, "sets " + extra + " on a next hop of " + dest + ", which a " + platform + "_static_route step doesn't take"
						}
						addr, _ := itemValue(in, hop, "forward_router_address")
						if addr == "" {
							return nil, "has a next hop of " + dest + " without a forward_router_address"
						}
						hops = append(hops, addr)
						// The step's distance is the route's, so every next hop
						// has to have the same one.
						d, _ := itemValue(in, hop, "admin_distance")
						if i > 0 && d != distance {
							return nil, "sets a different admin_distance on next hops of " + dest + ", and a vyos_static_route step has one distance for the route"
						}
						distance = d
					}
					if in.problem != "" {
						return nil, in.problem
					}
					if dest == "" || len(hops) == 0 {
						return nil, "has a route without a dest and a next hop"
					}
					if addsToLists(in) {
						return nil, "sets next hops for " + dest + " under state: merged, which adds them to the ones the route has; a " + platform + "_static_route step's next_hops are all of them, so write every next hop the route should have, or use state: replaced"
					}
					attrs := []attr{s("prefix", dest), {key: "next_hops", val: strList(hops)}}
					if distance != "" {
						n, err := strconv.Atoi(distance)
						if err != nil {
							return nil, fmt.Sprintf("sets admin_distance %q on %s, which isn't a whole number", distance, dest)
						}
						attrs = append(attrs, attr{key: "distance", val: cty.NumberIntVal(int64(n))})
					}
					steps = append(steps, step{module: platform + "_static_route", attrs: attrs, suffix: itemSuffix("route_", dest)})
				}
			}
		}
		if len(steps) == 0 {
			return nil, "sets no routes"
		}
		return steps, ""
	}
}

// networkUser converts eos_user, junos_user and vyos_user, one account. A
// password is never read: the step gets a TODO to set password_wo from a
// secret instead, as a Linux user's does.
func networkUser(platform string) func(*input) ([]step, string) {
	return func(in *input) ([]step, string) {
		for _, k := range []string{"aggregate", "purge"} {
			if in.has(k) {
				return nil, "sets " + k + ", which works on every account at once; a " + platform + "_user step manages one"
			}
		}
		if st := in.str("state"); st != "" && st != "present" {
			return nil, "has state " + st + "; a " + platform + "_user step removes its account when the step is removed, with on_remove"
		}
		if in.has("encrypted_password") {
			return nil, "sets encrypted_password, a hash a " + platform + "_user step can't take; set password_wo from a secret instead"
		}
		if u := in.str("update_password"); u == "on_create" {
			return nil, "sets update_password: on_create, and a " + platform + "_user step sets password_wo whenever it changes"
		}
		name := in.str("name")
		if name == "" {
			return nil, "has no name"
		}
		attrs := []attr{s("name", name)}
		switch platform {
		case "eos":
			if in.has("privilege") {
				attrs = append(attrs, in.number("privilege"))
			}
			attrs = in.optional(attrs, "role", "role")
			attrs = in.optional(attrs, "ssh_key", "sshkey")
			if in.has("nopassword") {
				attrs = append(attrs, attr{key: "nopassword", val: cty.BoolVal(in.bool("nopassword", false))})
			}
		case "junos":
			role := in.str("role")
			if role == "" {
				return nil, "has no role, and a junos_user step needs its class"
			}
			attrs = append(attrs, s("class", role))
			if in.has("sshkey") {
				// junos_user merges the key in, and the step's ssh_keys are all
				// of them: converted, the account's other keys would be deleted.
				return nil, "sets sshkey, which junos_user adds to the account's keys; a junos_user step's ssh_keys are all of them, so list every key the account should have"
			}
			if in.has("full_name") {
				return nil, "sets full_name, which a junos_user step doesn't take"
			}
			if in.has("active") && !in.bool("active", true) {
				return nil, "sets active: false, and a junos_user step keeps its account active"
			}
		case "vyos":
			attrs = in.optional(attrs, "full_name", "full_name")
			var keys []string
			for _, k := range seq(in.args["public_keys"]) {
				m := mapping(k)
				typ, key, comment := in.render("public_keys", scalar(m["type"])), in.render("public_keys", scalar(m["key"])), in.render("public_keys", scalar(m["name"]))
				if typ == "" || key == "" {
					return nil, "has a public key without its type and key"
				}
				keys = append(keys, strings.TrimSpace(typ+" "+key+" "+comment))
			}
			in.ignore("public_keys")
			if len(keys) > 0 {
				attrs = append(attrs, attr{key: "ssh_keys", val: strList(keys)})
			}
		}
		if in.problem != "" {
			return nil, in.problem
		}
		var notes []string
		if in.has("configured_password") {
			in.ignore("configured_password", "update_password")
			notes = append(notes, "TODO(convert): Set password_wo from an ephemeral variable holding the task's configured_password. It isn't copied here.")
		}
		in.ignore("update_password")
		return one(platform+"_user", attrs, notes...)
	}
}
