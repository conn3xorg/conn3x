// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Roles load their per-OS values with one include_vars or several. A later
// file's keys win, and an include can be for some hosts only:
//
//	- include_vars: "{{ ansible_facts.os_family }}.yml"
//	- include_vars: "{{ item }}"
//	  with_first_found:
//	    - files: ["{{ ansible_facts.distribution }}-{{ ansible_facts.distribution_major_version }}.yml"]
//	      skip: true
//	- include_vars: "{{ ansible_facts.distribution }}.yml"
//	  when: ansible_facts.os_family == 'Debian'
//
// For each distribution and release Conn3x configures, familyVars works out
// the files Ansible would load, in order, and merges their values. Each
// distinct list of files is one entry on the axis values are looked up by.

// varsInclude is one include_vars task familyVars reads: the files it tries,
// first match wins, whether a host may load none, and which hosts it runs on.
type varsInclude struct {
	node      *yaml.Node
	templates [][]namePart
	skip      bool
	when      []hostTest // all must hold
}

// hostTest is a when condition on the host's family or distribution: true
// when the host's name, in Ansible's spelling, is among names, or isn't,
// with not.
type hostTest struct {
	fact  string // "family" or "distribution"
	not   bool
	names []string
}

func (t hostTest) holds(fam, d string) bool {
	v := fam
	if t.fact == "distribution" {
		v = d
	}
	in := false
	for _, n := range t.names {
		in = in || n == v
	}
	return in != t.not
}

// hcl is the test as an expression over the locals versionBlocks writes.
func (t hostTest) hcl() string {
	ref := "local.os_family_name[name]"
	if t.fact == "distribution" {
		ref = "local.os_distribution[name]"
	}
	quoted := make([]string, len(t.names))
	for i, n := range t.names {
		quoted[i] = fmt.Sprintf("%q", n)
	}
	out := fmt.Sprintf("contains([%s], %s)", strings.Join(quoted, ", "), ref)
	if t.not {
		out = "!" + out
	}
	return out
}

func (inc varsInclude) applies(fam, d string) bool {
	for _, t := range inc.when {
		if !t.holds(fam, d) {
			return false
		}
	}
	return true
}

// hostTests reads a when that only tests the family or the distribution.
func hostTests(w *yaml.Node) ([]hostTest, bool) {
	if w == nil {
		return nil, true
	}
	var conds []string
	switch w.Kind {
	case yaml.ScalarNode:
		conds = []string{w.Value}
	case yaml.SequenceNode:
		for _, e := range w.Content {
			if e.Kind != yaml.ScalarNode {
				return nil, false
			}
			conds = append(conds, e.Value)
		}
	default:
		return nil, false
	}
	var tests []hostTest
	for _, c := range conds {
		c = strings.Join(strings.Fields(c), " ")
		if m := familyCompare.FindStringSubmatch(c); m != nil {
			tests = append(tests, hostTest{fact: "family", not: m[1] == "!=", names: []string{m[2]}})
			continue
		}
		if m := distributionCompare.FindStringSubmatch(c); m != nil {
			tests = append(tests, hostTest{fact: "distribution", not: m[1] == "!=", names: []string{m[2]}})
			continue
		}
		if m := familyIn.FindStringSubmatch(c); m != nil {
			var names []string
			for _, q := range strings.Split(m[2], ",") {
				w := quotedWord.FindStringSubmatch(q)
				if w == nil {
					return nil, false
				}
				names = append(names, w[1])
			}
			tests = append(tests, hostTest{fact: "family", not: m[1] == "not in", names: names})
			continue
		}
		return nil, false
	}
	return tests, true
}

// readInclude reads an include_vars task. is is false for any other task;
// ok false for an include the converter can't follow.
func (c *converter) readInclude(n *yaml.Node) (inc varsInclude, is, ok bool) {
	t := mapping(n)
	arg, is := t["include_vars"]
	if !is {
		arg, is = t["ansible.builtin.include_vars"]
	}
	if !is {
		return inc, false, false
	}
	for k := range t {
		if k != "name" && k != "include_vars" && k != "ansible.builtin.include_vars" && k != "with_first_found" && k != "when" {
			return inc, true, false
		}
	}
	if arg.Kind == yaml.MappingNode && len(arg.Content) == 2 && arg.Content[0].Value == "file" {
		arg = arg.Content[1]
	}
	if arg.Kind != yaml.ScalarNode {
		return inc, true, false
	}
	if inc.when, ok = hostTests(t["when"]); !ok {
		return inc, true, false
	}
	inc.node = n
	if ff := t["with_first_found"]; ff != nil {
		if m := bareRef.FindStringSubmatch(arg.Value); m == nil || m[1] != "item" {
			return inc, true, false
		}
		inc.templates, inc.skip, ok = firstFoundEntries(ff)
		return inc, true, ok
	}
	segs, ok := nameTemplate(arg.Value)
	if !ok {
		return inc, true, false
	}
	inc.templates = [][]namePart{segs}
	return inc, true, true
}

// familyVars finds the role's include_vars tasks among its tasks and reads
// the files a Debian or Red Hat family host would load. It returns the
// includes, the axis values are looked up by, whether that axis is per list
// of files rather than per family, the values by axis entry and name, and
// for a value it can't use, such as a list, why; or nil includes when
// there's none it can follow or a file is missing, and the includes then go
// to review as before.
func (c *converter) familyVars(tasks []*yaml.Node) ([]varsInclude, []osFamily, bool, map[string]map[string]string, map[string]map[string]string) {
	var incs []varsInclude
	for _, n := range tasks {
		if inc, _, ok := c.readInclude(n); ok {
			incs = append(incs, inc)
		}
	}
	if len(incs) == 0 {
		return nil, nil, false, nil, nil
	}
	type combo struct {
		fam   osFamily
		files []string
	}
	var combos []combo
	seen := map[string]bool{}
	failed := false            // some hosts would stop at an include that finds no file
	loads := map[string]bool{} // a family some of whose hosts load their files
	for _, f := range osFamilies {
		for _, d := range familyDistributions[f.ansible] {
			for _, v := range osVersions[d] {
				var files []string
				stops := false
				for _, inc := range incs {
					if !inc.applies(f.ansible, d) {
						continue
					}
					file, ok := c.firstFile(inc.templates, f.ansible, d, v)
					if !ok {
						return nil, nil, false, nil, nil
					}
					if file == "" {
						stops = stops || !inc.skip
						continue
					}
					files = append(files, file)
				}
				if stops {
					failed = true
					continue
				}
				loads[f.conn3x] = true
				k := f.conn3x + "/" + strings.Join(files, "+")
				if !seen[k] {
					seen[k] = true
					combos = append(combos, combo{fam: f, files: files})
				}
			}
		}
	}
	// A family none of whose hosts get past the includes doesn't read as
	// per-OS values at all; leave the includes for review.
	if !loads["debian"] || !loads["redhat"] {
		return nil, nil, false, nil, nil
	}
	byFam := map[string]int{}
	for _, cb := range combos {
		byFam[cb.fam.conn3x]++
	}
	// Values are a family's when each family's hosts load the same files and
	// none stops; otherwise the circuit works out each host's files at plan.
	versioned := failed || byFam["debian"] > 1 || byFam["redhat"] > 1
	var axis []osFamily
	for _, cb := range combos {
		a := cb.fam
		for _, file := range cb.files {
			a.files = append(a.files, "vars/"+file)
		}
		a.file = strings.Join(a.files, " and ")
		if versioned {
			a.key = cb.fam.conn3x + "/" + strings.Join(cb.files, "+")
		}
		axis = append(axis, a)
	}
	sort.SliceStable(axis, func(i, j int) bool { return axis[i].id() < axis[j].id() })
	vals, whys, ok := c.loadFamilyFiles(axis)
	if !ok {
		return nil, nil, false, nil, nil
	}
	return incs, axis, versioned, vals, whys
}

// loadFamilyFiles reads each axis entry's variables files, in order, a later
// file's keys winning, by entry. An entry with no file has no values. false
// when a file can't be read.
func (c *converter) loadFamilyFiles(axis []osFamily) (map[string]map[string]string, map[string]map[string]string, bool) {
	vals, whys := map[string]map[string]string{}, map[string]map[string]string{}
	for _, f := range osFamilies {
		vals[f.conn3x], whys[f.conn3x] = map[string]string{}, map[string]string{}
	}
	for _, f := range axis {
		vals[f.id()], whys[f.id()] = map[string]string{}, map[string]string{}
		for _, rel := range f.files {
			path := c.path(rel)
			src, err := os.ReadFile(path)
			var doc yaml.Node
			if err != nil || !exactlyNamed(path) || parse(src, &doc) != nil || len(doc.Content) == 0 {
				return nil, nil, false
			}
			for _, kv := range pairs(doc.Content[0]) {
				k := kv[0].Value
				delete(vals[f.id()], k)
				delete(whys[f.id()], k)
				if v, _, why := plainValue(kv[1]); why == "" {
					vals[f.id()][k] = v
				} else {
					whys[f.id()][k] = why
				}
			}
		}
	}
	return vals, whys, true
}
