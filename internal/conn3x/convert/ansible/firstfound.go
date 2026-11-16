// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Roles often load their per-OS values with the first file that exists:
//
//	- include_vars: "{{ item }}"
//	  with_first_found:
//	    - "{{ ansible_facts.distribution }}-{{ ansible_facts.distribution_version }}.yml"
//	    - "{{ ansible_facts.distribution }}.yml"
//	    - "{{ ansible_facts.os_family }}.yml"
//	    - "default.yml"
//
// For each family, firstFound works out which file each distribution in it
// would load, as Ansible does, first match wins. It's a family's values when
// every distribution in the family lands on the same file.

// familyDistributions are the distributions Conn3x configures, by Ansible's
// family and distribution names.
var familyDistributions = map[string][]string{
	"Debian": {"Debian", "Ubuntu"},
	"RedHat": {"RedHat", "Rocky", "AlmaLinux", "Fedora"},
}

var (
	jinjaExpr        = regexp.MustCompile(`\{\{\s*(.*?)\s*\}\}`)
	distributionName = regexp.MustCompile(`^ansible_(?:facts\.distribution|facts\[["']distribution["']\]|distribution)$`)
	familyName       = regexp.MustCompile(`^` + familyFact + `$`)
)

// firstFound reads a with_first_found list and returns, by family, the file
// under the role each family loads. A family that loads none, with skip set,
// is left out. false when the list isn't plain enough to tell, or when a
// file that would be picked depends on something the converter can't know,
// such as the distribution's version.
func (c *converter) firstFound(n *yaml.Node) (map[string]string, bool) {
	var entries []string
	skip := false
	add := func(n *yaml.Node) bool {
		switch n.Kind {
		case yaml.ScalarNode:
			entries = append(entries, n.Value)
		case yaml.MappingNode:
			m := mapping(n)
			for k := range m {
				if k != "files" && k != "skip" {
					return false // paths, or something else that changes where it looks
				}
			}
			if b, ok := yamlBool(m["skip"]); ok {
				skip = b
			}
			for _, f := range seq(m["files"]) {
				if f.Kind != yaml.ScalarNode {
					return false
				}
				entries = append(entries, f.Value)
			}
		default:
			return false
		}
		return true
	}
	if n.Kind == yaml.SequenceNode {
		for _, e := range n.Content {
			if !add(e) {
				return nil, false
			}
		}
	} else if !add(n) {
		return nil, false
	}

	out := map[string]string{}
	for _, f := range osFamilies {
		picked := ""
		for i, d := range familyDistributions[f.ansible] {
			file, ok := c.firstFile(entries, f.ansible, d)
			if !ok || file == "" && !skip {
				return nil, false
			}
			if i > 0 && file != picked {
				return nil, false // the family's distributions load different files
			}
			picked = file
		}
		if picked != "" {
			out[f.conn3x] = picked
		}
	}
	return out, true
}

// firstFile is the first entry that names an existing file for distribution
// d in family fam, as a path under the role, or "" for none. false when an
// entry the converter can't fill in could match a file.
func (c *converter) firstFile(entries []string, fam, d string) (string, bool) {
	for _, e := range entries {
		unknown := false
		name := jinjaExpr.ReplaceAllStringFunc(e, func(m string) string {
			expr := jinjaExpr.FindStringSubmatch(m)[1]
			switch {
			case distributionName.MatchString(expr):
				return d
			case familyName.MatchString(expr):
				return fam
			}
			unknown = true
			return "*"
		})
		if strings.ContainsAny(strings.ReplaceAll(name, "*", ""), "{}") {
			return "", false
		}
		rel := name
		if !strings.HasPrefix(rel, "vars/") {
			rel = "vars/" + rel
		}
		if unknown {
			if matches, _ := filepath.Glob(c.path(rel)); len(matches) > 0 {
				return "", false // whether it loads depends on a value the converter doesn't know
			}
			continue
		}
		if st, err := os.Stat(c.path(rel)); err == nil && !st.IsDir() {
			return rel, true
		}
	}
	return "", true
}
