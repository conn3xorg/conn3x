// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// A role often keeps a list per OS in vars/, such as the packages to
// install, and defaults a variable to it:
//
//	- set_fact:
//	    apache_packages: "{{ __apache_packages | list }}"
//	  when: apache_packages is not defined
//
// The list is read here the way familyVars reads text, by axis entry, and a
// step looping over it gets for_each = the caller's list, or the one the
// host's vars file sets.

// listRef matches {{ name }} or {{ name | list }}.
var listRef = regexp.MustCompile(`^\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\|\s*list\s*)?\}\}$`)

// familyLists reads the lists of plain values each axis entry's vars files
// set, a later file's keys winning, by entry.
func (c *converter) familyLists(axis []osFamily) map[string]map[string][]string {
	out := map[string]map[string][]string{}
	for _, f := range axis {
		out[f.id()] = map[string][]string{}
		for _, rel := range f.files {
			src, err := os.ReadFile(c.path(rel))
			var doc yaml.Node
			if err != nil || parse(src, &doc) != nil || len(doc.Content) == 0 {
				continue
			}
			for _, kv := range pairs(doc.Content[0]) {
				delete(out[f.id()], kv[0].Value)
				if items, ok := plainList(kv[1]); ok {
					out[f.id()][kv[0].Value] = items
				}
			}
		}
	}
	return out
}

// listDefault is a variable the caller can set to a list, else the list
// the host's vars file sets as src.
type listDefault struct {
	src  string
	gaps map[string]bool // axis entries whose files set no such list
}

// listDefaults finds the set_fact tasks that default a variable to a list
// from vars/, and records them as defaults.
func (c *converter) listDefaults(tasks []taskAt, vars map[string]string) map[string]listDefault {
	out := map[string]listDefault{}
	r := c.role
	if r == nil || r.familyLists == nil {
		return out
	}
	for _, ta := range tasks {
		t := mapping(ta.node)
		want := 2
		if t["name"] != nil {
			want = 3
		}
		sf := t["set_fact"]
		if sf == nil {
			sf = t["ansible.builtin.set_fact"]
		}
		if len(t) != want || sf == nil || t["when"] == nil {
			continue
		}
		kv := pairs(sf)
		if len(kv) != 1 || kv[0][1].Kind != yaml.ScalarNode {
			continue
		}
		x := kv[0][0].Value
		m := listRef.FindStringSubmatch(strings.TrimSpace(kv[0][1].Value))
		if m == nil || !identifier.MatchString(x) || reserved[x] || r.defaults[x] != nil || has(vars, x) {
			continue
		}
		if strings.Join(strings.Fields(scalar(t["when"])), " ") != x+" is not defined" {
			continue
		}
		d := listDefault{src: m[1], gaps: map[string]bool{}}
		some := false
		for _, f := range c.axisFor(osFamilies) {
			if _, ok := r.familyLists[f.id()][m[1]]; ok {
				some = true
			} else {
				d.gaps[f.id()] = true
			}
		}
		if !some || (len(d.gaps) > 0 && !r.gapTrusted(m[1])) {
			continue
		}
		out[x] = d
		r.defaultTasks[taskKey(ta.file, ta.node)] = x
	}
	return out
}

// listForEach is the for_each of a step looping over the list default x:
// the caller's list when set, else the host's vars file's. present are the
// axis entries that set it. why is set when an entry's list can't be used.
func (c *converter) listForEach(x string) (expr string, present []osFamily, why string) {
	d := c.role.listDefaults[x]
	var parts []string
	for _, f := range c.axisFor(osFamilies) {
		items, ok := c.role.familyLists[f.id()][d.src]
		if !ok {
			continue
		}
		seen := map[string]bool{}
		var quoted []string
		for _, it := range items {
			if seen[it] {
				return "", nil, fmt.Sprintf("loops over %q, which %s lists %q in twice, and a step runs once per item", x, f.where(), it)
			}
			seen[it] = true
			quoted = append(quoted, hclString(it))
		}
		parts = append(parts, fmt.Sprintf("%s = [%s]", hclString(f.id()), strings.Join(quoted, ", ")))
		present = append(present, f)
	}
	return fmt.Sprintf("var.%s != null ? var.%s : { %s }[%s]", x, x, strings.Join(parts, ", "), c.axisExpr()), present, ""
}
