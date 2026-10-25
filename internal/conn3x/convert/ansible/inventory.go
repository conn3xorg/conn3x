// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Inventory is an Ansible inventory: hosts, the groups they're in, and the
// variables set on each.
type Inventory struct {
	hostVars map[string]map[string]string
	groups   map[string]*groupDef
}

type groupDef struct {
	hosts    []string
	children []string
	vars     map[string]string
}

// ReadInventory reads an INI or YAML inventory file.
func ReadInventory(path string) (*Inventory, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	inv := &Inventory{hostVars: map[string]map[string]string{}, groups: map[string]*groupDef{}}
	if strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml") {
		err = inv.readYAML(src)
	} else {
		err = inv.readINI(string(src))
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return inv, nil
}

func (inv *Inventory) group(name string) *groupDef {
	g, ok := inv.groups[name]
	if !ok {
		g = &groupDef{vars: map[string]string{}}
		inv.groups[name] = g
	}
	return g
}

func (inv *Inventory) addHost(group, name string, vars map[string]string) error {
	if strings.ContainsAny(name, "[]") {
		return fmt.Errorf("host pattern %q: ranges aren't supported yet; list the hosts one by one", name)
	}
	g := inv.group(group)
	g.hosts = append(g.hosts, name)
	hv, ok := inv.hostVars[name]
	if !ok {
		hv = map[string]string{}
		inv.hostVars[name] = hv
	}
	for k, v := range vars {
		hv[k] = v
	}
	return nil
}

func (inv *Inventory) readINI(src string) error {
	section, kind := "ungrouped", ""
	sc := bufio.NewScanner(strings.NewReader(src))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section, kind, _ = strings.Cut(strings.Trim(line, "[]"), ":")
			inv.group(section)
			continue
		}
		fields := strings.Fields(line)
		switch kind {
		case "vars":
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				return fmt.Errorf("line %d: expected key=value", n)
			}
			inv.group(section).vars[strings.TrimSpace(k)] = unquote(strings.TrimSpace(v))
		case "children":
			inv.group(section).children = append(inv.group(section).children, fields[0])
			inv.group(fields[0])
		case "":
			vars := map[string]string{}
			for _, kv := range fields[1:] {
				if k, v, ok := strings.Cut(kv, "="); ok {
					vars[k] = unquote(v)
				}
			}
			if err := inv.addHost(section, fields[0], vars); err != nil {
				return fmt.Errorf("line %d: %w", n, err)
			}
		default:
			return fmt.Errorf("line %d: unknown section kind %q", n, kind)
		}
	}
	return sc.Err()
}

func unquote(s string) string { return strings.Trim(s, `"'`) }

func (inv *Inventory) readYAML(src []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return err
	}
	if len(doc.Content) == 0 {
		return nil
	}
	for name, g := range mapping(doc.Content[0]) {
		if err := inv.yamlGroup(name, g); err != nil {
			return err
		}
	}
	return nil
}

func (inv *Inventory) yamlGroup(name string, node *yaml.Node) error {
	g := inv.group(name)
	m := mapping(node)
	for host, hv := range mapping(m["hosts"]) {
		vars := map[string]string{}
		for k, v := range mapping(hv) {
			vars[k] = scalar(v)
		}
		if err := inv.addHost(name, host, vars); err != nil {
			return err
		}
	}
	for k, v := range mapping(m["vars"]) {
		g.vars[k] = scalar(v)
	}
	for child, cn := range mapping(m["children"]) {
		g.children = append(g.children, child)
		if err := inv.yamlGroup(child, cn); err != nil {
			return err
		}
	}
	return nil
}

// members collects the hosts in a group and its children.
func (inv *Inventory) members(name string, seen map[string]bool, out map[string]bool) {
	g, ok := inv.groups[name]
	if !ok || seen[name] {
		return
	}
	seen[name] = true
	for _, h := range g.hosts {
		out[h] = true
	}
	for _, c := range g.children {
		inv.members(c, seen, out)
	}
}

func (inv *Inventory) depth(name string) int {
	best := 0
	for parent, g := range inv.groups {
		for _, c := range g.children {
			if c == name && parent != name {
				if d := inv.depth(parent) + 1; d > best {
					best = d
				}
			}
		}
	}
	return best
}

// varsFor resolves a host's variables: groups from the outermost in, then
// the host's own.
func (inv *Inventory) varsFor(host string) map[string]string {
	type held struct {
		name  string
		depth int
	}
	var groups []held
	for name := range inv.groups {
		in := map[string]bool{}
		inv.members(name, map[string]bool{}, in)
		if in[host] {
			groups = append(groups, held{name, inv.depth(name)})
		}
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].depth != groups[j].depth {
			return groups[i].depth < groups[j].depth
		}
		return groups[i].name < groups[j].name
	})
	out := map[string]string{}
	if all, ok := inv.groups["all"]; ok {
		for k, v := range all.vars {
			out[k] = v
		}
	}
	for _, g := range groups {
		for k, v := range inv.groups[g.name].vars {
			out[k] = v
		}
	}
	for k, v := range inv.hostVars[host] {
		out[k] = v
	}
	return out
}

// Group is the resolved hosts of one group, with their variables.
type Group struct {
	hosts map[string]map[string]string
}

// Group resolves a group by name, including "all"; nil if there's none.
func (inv *Inventory) Group(name string) *Group {
	in := map[string]bool{}
	if name == "all" {
		for h := range inv.hostVars {
			in[h] = true
		}
	} else {
		if _, ok := inv.groups[name]; !ok {
			return nil
		}
		inv.members(name, map[string]bool{}, in)
	}
	g := &Group{hosts: map[string]map[string]string{}}
	for h := range in {
		g.hosts[h] = inv.varsFor(h)
	}
	return g
}

// Addresses maps each host's name to where to reach it.
func (g *Group) Addresses() map[string]string {
	out := map[string]string{}
	for h, vars := range g.hosts {
		addr := h
		if a := vars["ansible_host"]; a != "" {
			addr = a
		}
		out[h] = addr
	}
	return out
}

// Common returns a variable every host in the group sets to the same value.
func (g *Group) Common(key string) (string, bool) {
	val, first := "", true
	for _, vars := range g.hosts {
		v, ok := vars[key]
		if !ok || (!first && v != val) {
			return "", false
		}
		val, first = v, false
	}
	return val, !first
}

// Values lists the distinct values hosts set for a variable.
func (g *Group) Values(key string) []string {
	seen := map[string]bool{}
	for _, vars := range g.hosts {
		if v, ok := vars[key]; ok {
			seen[v] = true
		}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
