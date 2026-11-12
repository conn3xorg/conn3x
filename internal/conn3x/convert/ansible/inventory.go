// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Inventory is an Ansible inventory: hosts, the groups they're in, and the
// variables set on each.
type Inventory struct {
	hostVars map[string]map[string]string
	groups   map[string]*groupDef
	// dirGroupVars and dirHostVars are what group_vars/ and host_vars/
	// beside the inventory set, which outrank the inventory file's own.
	dirGroupVars map[string]map[string]string
	dirHostVars  map[string]map[string]string
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
	// An INI file doesn't go through parse, so the NUL check is repeated here.
	if strings.Contains(string(src), "\x00") {
		return nil, fmt.Errorf("%s has a NUL byte, which the converter doesn't accept anywhere in a file it reads", path)
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
	// depth follows children up to their parents, so a loop would never end.
	for name := range inv.groups {
		if inv.descends(name, name, map[string]bool{}) {
			return nil, fmt.Errorf("%s: group %q is a child of itself", path, name)
		}
	}
	dir := filepath.Dir(path)
	if inv.dirGroupVars, err = readVarsDir(filepath.Join(dir, "group_vars")); err != nil {
		return nil, err
	}
	if inv.dirHostVars, err = readVarsDir(filepath.Join(dir, "host_vars")); err != nil {
		return nil, err
	}
	return inv, nil
}

// readVarsDir reads a group_vars or host_vars directory as Ansible does:
// for each name, a file called name, name.yml, name.yaml or name.json, or
// every such file under a directory called name, in lexical order, later
// files winning. Only plain values are kept: a list or a map isn't, and
// neither is a value encrypted with Ansible Vault, which a whole encrypted
// file stops on.
func readVarsDir(dir string) (map[string]map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]string{}
	add := func(name, path string) error {
		ext := filepath.Ext(path)
		if ext != "" && ext != ".yml" && ext != ".yaml" && ext != ".json" {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.HasPrefix(string(src), "$ANSIBLE_VAULT") {
			return fmt.Errorf("%s is encrypted with Ansible Vault, which Conn3x can't read", path)
		}
		var doc yaml.Node
		if err := parse(src, &doc); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if out[name] == nil {
			out[name] = map[string]string{}
		}
		if len(doc.Content) == 0 {
			return nil
		}
		for k, v := range mapping(doc.Content[0]) {
			if v.Kind == yaml.ScalarNode && v.Value != vaultMark {
				out[name][k] = v.Value
			}
		}
		return nil
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if !e.IsDir() {
			if err := add(strings.TrimSuffix(e.Name(), filepath.Ext(e.Name())), path); err != nil {
				return nil, err
			}
			continue
		}
		var files []string
		_ = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				files = append(files, p)
			}
			return nil
		})
		sort.Strings(files)
		for _, f := range files {
			if err := add(e.Name(), f); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// descends reports whether target is below name in the group tree.
func (inv *Inventory) descends(name, target string, seen map[string]bool) bool {
	if seen[name] {
		return false
	}
	seen[name] = true
	for _, c := range inv.groups[name].children {
		if c == target || (inv.groups[c] != nil && inv.descends(c, target, seen)) {
			return true
		}
	}
	return false
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
	if err := parse(src, &doc); err != nil {
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

// varsFor resolves a host's variables, in Ansible's order: the inventory
// file's groups from the outermost in, then group_vars/ the same way, then
// the host's own from the file, then host_vars/.
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
	// group_vars/ outranks every group's vars in the inventory file, with
	// all first and the deepest group last, as there.
	for k, v := range inv.dirGroupVars["all"] {
		out[k] = v
	}
	for _, g := range groups {
		if g.name == "all" {
			continue
		}
		for k, v := range inv.dirGroupVars[g.name] {
			out[k] = v
		}
	}
	for k, v := range inv.hostVars[host] {
		out[k] = v
	}
	for k, v := range inv.dirHostVars[host] {
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

// Encrypted reports whether an inventory value stands for one encrypted
// with Ansible Vault, which can't be read.
func Encrypted(v string) bool { return v == vaultMark }

// Names lists the group's hosts, sorted.
func (g *Group) Names() []string {
	out := make([]string, 0, len(g.hosts))
	for h := range g.hosts {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// Vars is a host's variables, resolved as Ansible would: groups from the
// outermost in, then the host's own.
func (g *Group) Vars(host string) map[string]string { return g.hosts[host] }

// GroupNames lists the inventory's groups, sorted.
func (inv *Inventory) GroupNames() []string {
	out := make([]string, 0, len(inv.groups))
	for n := range inv.groups {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
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
