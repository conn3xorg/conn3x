// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"

	"github.com/opentofu/opentofu/internal/conn3x/convert/ansible"
)

// circuitSSHVars maps the circuit ssh settings -circuits carries over to
// the inventory variables sshFor reads.
var circuitSSHVars = map[string]string{
	"user":             "ansible_user",
	"port":             "ansible_port",
	"private_key_file": "ansible_ssh_private_key_file",
	"known_hosts_file": "conn3x_ssh_known_hosts_file",
	"host_key":         "conn3x_ssh_host_key",
	"become":           "conn3x_ssh_become",
	"timeout":          "conn3x_ssh_timeout",
}

// circuitInventory reads the circuits in dir's .tf and .circuit.hcl files
// into an inventory: a group per circuit, named after it, holding its
// hosts, each with the circuit's ssh settings and its own host object's.
// Only literal values are read: hosts or ssh settings that need variables,
// locals or functions to work out are an error, which names them.
func circuitInventory(dir string) (*ansible.Inventory, error) {
	var files []string
	for _, pat := range []string{"*.tf", "*.circuit.hcl"} {
		m, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			return nil, err
		}
		files = append(files, m...)
	}
	sort.Strings(files)
	inv := ansible.NewInventory()
	found := 0
	p := hclparse.NewParser()
	for _, path := range files {
		f, diags := p.ParseHCLFile(path)
		if diags.HasErrors() {
			return nil, diags
		}
		content, _, diags := f.Body.PartialContent(&hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "circuit", LabelNames: []string{"name"}}}})
		if diags.HasErrors() {
			return nil, diags
		}
		for _, b := range content.Blocks {
			if err := addCircuit(inv, b, dir); err != nil {
				return nil, fmt.Errorf("%s: circuit %q: %w", path, b.Labels[0], err)
			}
			found++
		}
	}
	if found == 0 {
		abs, _ := filepath.Abs(dir)
		return nil, fmt.Errorf("no circuit in %s's .tf or .circuit.hcl files", abs)
	}
	return inv, nil
}

func addCircuit(inv *ansible.Inventory, b *hcl.Block, dir string) error {
	body, _, diags := b.Body.PartialContent(&hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{{Name: "hosts", Required: true}},
		Blocks:     []hcl.BlockHeaderSchema{{Type: "ssh"}},
	})
	if diags.HasErrors() {
		return diags
	}
	common := map[string]string{}
	for _, s := range body.Blocks.OfType("ssh") {
		attrs, diags := s.Body.JustAttributes()
		if diags.HasErrors() {
			return diags
		}
		for name, a := range attrs {
			key, ok := circuitSSHVars[name]
			if !ok {
				return fmt.Errorf("ssh %s isn't something conn3x run -circuits carries over yet; use an inventory with -i", name)
			}
			v, err := literal(a.Expr, "ssh "+name)
			if err != nil {
				return err
			}
			common[key] = v
		}
	}
	hosts, err := literalValue(body.Attributes["hosts"].Expr, "hosts")
	if err != nil {
		return err
	}
	if !hosts.Type().IsObjectType() && !hosts.Type().IsMapType() {
		return fmt.Errorf("hosts must be a map of host names to addresses or host objects")
	}
	byName := map[string]cty.Value{}
	var names []string
	for it := hosts.ElementIterator(); it.Next(); {
		k, v := it.Element()
		byName[k.AsString()] = v
		names = append(names, k.AsString())
	}
	slices.Sort(names)
	for _, name := range names {
		h := byName[name]
		vars := map[string]string{}
		if h.Type().IsObjectType() || h.Type().IsMapType() {
			for it := h.ElementIterator(); it.Next(); {
				k, v := it.Element()
				field := k.AsString()
				if field == "address" {
					if s, err := asString(v); err == nil {
						vars["ansible_host"] = s
					}
					continue
				}
				// Other fields are the host's own data, read in steps with
				// each.value, except the ssh settings it may override.
				if key, ok := circuitSSHVars[field]; ok {
					s, err := asString(v)
					if err != nil {
						return fmt.Errorf("host %s: %s: %w", name, field, err)
					}
					vars[key] = s
				}
			}
			if vars["ansible_host"] == "" {
				return fmt.Errorf("host %s is an object without an address", name)
			}
		} else {
			s, err := asString(h)
			if err != nil {
				return fmt.Errorf("host %s: %w", name, err)
			}
			vars["ansible_host"] = s
		}
		for k, v := range common {
			if _, set := vars[k]; !set {
				vars[k] = v
			}
		}
		// A relative path in a circuit is relative to its configuration, as
		// when OpenTofu runs there, not to wherever conn3x run is started.
		for _, k := range []string{"ansible_ssh_private_key_file", "conn3x_ssh_known_hosts_file"} {
			if p := vars[k]; p != "" && !filepath.IsAbs(p) && !strings.HasPrefix(p, "~") {
				vars[k] = filepath.Join(dir, p)
			}
		}
		// A host in two circuits must reach the same way from both: which
		// circuit's settings win would otherwise depend on file order.
		if had := inv.Group("all"); had != nil {
			if before := had.Vars(name); before != nil {
				for k, v := range vars {
					if old, ok := before[k]; ok && old != v {
						return fmt.Errorf("host %s is in another circuit too, with %s %q there and %q here; give it the same ssh settings in both, or use an inventory with -i", name, sshSettingOf(k), old, v)
					}
				}
			}
		}
		inv.AddHost(b.Labels[0], name, vars)
	}
	return nil
}

// sshSettingOf names the ssh setting behind an inventory variable.
func sshSettingOf(key string) string {
	if key == "ansible_host" {
		return "address"
	}
	for setting, k := range circuitSSHVars {
		if k == key {
			return setting
		}
	}
	return key
}

// literalValue is expr's value with no variables or functions: what a
// circuit writes out in full.
func literalValue(expr hcl.Expression, what string) (cty.Value, error) {
	v, diags := expr.Value(nil)
	if diags.HasErrors() {
		return cty.NilVal, fmt.Errorf("%s needs variables, locals or functions to work out, which conn3x run -circuits doesn't evaluate yet; write it out, or use an inventory with -i", what)
	}
	return v, nil
}

func literal(expr hcl.Expression, what string) (string, error) {
	v, err := literalValue(expr, what)
	if err != nil {
		return "", err
	}
	s, err := asString(v)
	if err != nil {
		return "", fmt.Errorf("%s: %w", what, err)
	}
	return s, nil
}

func asString(v cty.Value) (string, error) {
	if v.IsNull() || !v.IsKnown() {
		return "", fmt.Errorf("must be set")
	}
	s, err := convert.Convert(v, cty.String)
	if err != nil {
		return "", fmt.Errorf("must be a string, number or bool")
	}
	return strings.TrimSpace(s.AsString()), nil
}

// circuitsDirExists checks -circuits names a directory.
func circuitsDirExists(dir string) error {
	st, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("-circuits %s isn't a directory", dir)
	}
	return nil
}
