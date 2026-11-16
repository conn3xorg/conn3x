// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Roles often load their per-OS values with the first file that exists:
//
//	- include_vars: "{{ item }}"
//	  with_first_found:
//	    - "{{ ansible_facts.distribution }}-{{ ansible_facts.distribution_major_version }}.yml"
//	    - "{{ ansible_facts.distribution }}.yml"
//	    - "{{ ansible_facts.os_family }}.yml"
//	    - "default.yml"
//
// firstFound works out which file each distribution and release Conn3x
// configures would load, as Ansible does, first match wins. When every
// distribution in a family lands on the same file, the values are the
// family's, as for vars/<family>.yml. Otherwise each file is its own entry
// on the axis values are looked up by, and the circuit works out at plan
// which file each host would load (see versionBlocks).

// familyDistributions are the distributions Conn3x configures, by Ansible's
// family and distribution names.
var familyDistributions = map[string][]string{
	"Debian": {"Debian", "Ubuntu"},
	"RedHat": {"RedHat", "Rocky", "AlmaLinux", "Fedora"},
}

// osVersions are the releases of each distribution whose vars files the
// converter reads, as os-release's VERSION_ID gives them.
// shortcut: a fixed list that leaves out releases older than these; a host
// on one fails at plan if the role has a file just for it. Extend it when
// Conn3x supports another release.
var osVersions = map[string][]string{
	"Debian":    {"11", "12", "13"},
	"Ubuntu":    {"20.04", "22.04", "24.04", "26.04"},
	"RedHat":    {"8", "9", "10"},
	"Rocky":     {"8", "9", "10"},
	"AlmaLinux": {"8", "9", "10"},
	"Fedora":    {"40", "41", "42", "43", "44", "45"},
}

var (
	jinjaExpr        = regexp.MustCompile(`\{\{\s*(.*?)\s*\}\}`)
	distributionName = regexp.MustCompile(`^ansible_(?:facts\.distribution|facts\[["']distribution["']\]|distribution)$`)
	familyName       = regexp.MustCompile(`^` + familyFact + `$`)
	majorName        = regexp.MustCompile(`^` + majorFact + `$`)
	versionName      = regexp.MustCompile(`^ansible_(?:facts\.distribution_version|facts\[["']distribution_version["']\]|distribution_version)$`)
	quotedPart       = regexp.MustCompile(`^(?:'([^']*)'|"([^"]*)")$`)
)

// A namePart is a piece of a file name: literal text, or a fact the name is built from.
type namePart struct {
	lit  string
	fact string // "distribution", "major", "version" or "family"
}

// nameTemplate reads a with_first_found entry, such as
// "{{ ansible_facts.distribution + '-' + ansible_facts.distribution_major_version }}.yml",
// as segments. false for anything but those facts, quoted text and +.
func nameTemplate(e string) ([]namePart, bool) {
	var segs []namePart
	rest, ok := e, true
	for _, loc := range jinjaExpr.FindAllStringSubmatchIndex(e, -1) {
		segs = append(segs, namePart{lit: e[len(e)-len(rest) : loc[0]]})
		rest = e[loc[1]:]
		for _, part := range strings.Split(e[loc[2]:loc[3]], "+") {
			part = strings.TrimSpace(part)
			switch {
			case distributionName.MatchString(part):
				segs = append(segs, namePart{fact: "distribution"})
			case majorName.MatchString(part):
				segs = append(segs, namePart{fact: "major"})
			case versionName.MatchString(part):
				segs = append(segs, namePart{fact: "version"})
			case familyName.MatchString(part):
				segs = append(segs, namePart{fact: "family"})
			default:
				m := quotedPart.FindStringSubmatch(part)
				if m == nil {
					return nil, false
				}
				segs = append(segs, namePart{lit: m[1] + m[2]})
			}
		}
	}
	segs = append(segs, namePart{lit: rest})
	for _, s := range segs {
		ok = ok && !strings.ContainsAny(s.lit, "{}")
	}
	return segs, ok
}

// fill is the name a template gives a host of distribution d, release v,
// in family fam. A Debian or Red Hat family release's minor version isn't
// in os-release, so Ansible's distribution_version there is a pattern.
func fill(segs []namePart, fam, d, v string) (name string, pattern bool) {
	var b strings.Builder
	for _, s := range segs {
		switch s.fact {
		case "":
			b.WriteString(s.lit)
		case "distribution":
			b.WriteString(d)
		case "major":
			b.WriteString(strings.SplitN(v, ".", 2)[0])
		case "family":
			b.WriteString(fam)
		case "version":
			b.WriteString(v)
			if !strings.Contains(v, ".") && d != "Fedora" {
				b.WriteString(".*")
				pattern = true
			}
		}
	}
	return strings.TrimPrefix(b.String(), "vars/"), pattern
}

// axisFile is one vars file a with_first_found list loads, and the family
// of the hosts that load it. file is "" for hosts that load none, with skip.
type axisFile struct {
	fam  osFamily
	file string // under vars/
}

// firstFound reads a with_first_found list and returns the files it loads,
// with each one's family, and the list's templates. A family that loads
// none, with skip set, is left out. false when the list isn't plain enough
// to tell, or when a file that would be picked depends on something the
// converter can't know.
func (c *converter) firstFound(n *yaml.Node) ([]axisFile, [][]namePart, bool) {
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
				return nil, nil, false
			}
		}
	} else if !add(n) {
		return nil, nil, false
	}
	var templates [][]namePart
	for _, e := range entries {
		segs, ok := nameTemplate(e)
		if !ok {
			return nil, nil, false
		}
		templates = append(templates, segs)
	}

	var out []axisFile
	for _, f := range osFamilies {
		seen := map[string]bool{}
		for _, d := range familyDistributions[f.ansible] {
			for _, v := range osVersions[d] {
				file, ok := c.firstFile(templates, f.ansible, d, v)
				if !ok || file == "" && !skip {
					return nil, nil, false
				}
				if !seen[file] {
					seen[file] = true
					out = append(out, axisFile{fam: f, file: file})
				}
			}
		}
	}
	return out, templates, true
}

// firstFile is the first template that names an existing file under vars/
// for release v of distribution d in family fam, or "" for none. false when
// a name the converter can't fill in exactly could match a file.
func (c *converter) firstFile(templates [][]namePart, fam, d, v string) (string, bool) {
	for _, segs := range templates {
		name, pattern := fill(segs, fam, d, v)
		if pattern {
			if matches, _ := filepath.Glob(c.path("vars/" + name)); len(matches) > 0 {
				return "", false // whether it loads depends on a minor version the converter doesn't know
			}
			continue
		}
		if st, err := os.Stat(c.path("vars/" + name)); err == nil && !st.IsDir() {
			return name, true
		}
	}
	return "", true
}

// axisOf turns the files a with_first_found list loads into the axis values
// are looked up by: the two families when each family loads one file, as
// for vars/<family>.yml, or else one entry for each file a family loads.
func axisOf(files []axisFile) ([]osFamily, bool) {
	byFam := map[string]int{}
	for _, f := range files {
		byFam[f.fam.conn3x]++
	}
	versioned := false
	for _, n := range byFam {
		versioned = versioned || n > 1
	}
	var axis []osFamily
	for _, f := range files {
		a := f.fam
		if f.file != "" {
			a.file = "vars/" + f.file
			if versioned {
				a.key = f.fam.conn3x + "/" + f.file
			}
		}
		axis = append(axis, a)
	}
	sort.SliceStable(axis, func(i, j int) bool { return axis[i].id() < axis[j].id() })
	return axis, versioned
}

// versionBlocks is what a circuit whose values come from per-release vars
// files needs on top of familyBlocks: which file each host loads, worked out
// at plan as Ansible's with_first_found does, from the host's facts.
func (c *converter) versionBlocks(templates [][]namePart) string {
	var files []string
	if entries, err := os.ReadDir(c.path("vars")); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				files = append(files, fmt.Sprintf("%q", e.Name()))
			}
		}
	}
	var cands []string
	for _, segs := range templates {
		var b strings.Builder
		for _, s := range segs {
			switch s.fact {
			case "":
				b.WriteString(strings.NewReplacer(`\`, `\\`, `"`, `\"`, "${", "$${", "%{", "%%{").Replace(s.lit))
			case "distribution":
				b.WriteString("${local.os_distribution[name]}")
			case "major":
				b.WriteString(`${split(".", data.conn3x_host.facts[name].os_version)[0]}`)
			case "version":
				b.WriteString("${local.os_version[name]}")
			case "family":
				b.WriteString("${local.os_family_name[name]}")
			}
		}
		cands = append(cands, `"`+strings.TrimPrefix(b.String(), "vars/")+`"`)
	}
	return fmt.Sprintf(`
# Which of the role's vars files each host loads, the first of these that
# exists, as the role's with_first_found picks one. A host that loads a file
# the converter didn't read, such as one for an older release, fails at plan
# where a step looks its value up.
locals {
  os_distribution = { for name, h in var.hosts : name => lookup({
    debian = "Debian", ubuntu = "Ubuntu", rhel = "RedHat", rocky = "Rocky", almalinux = "AlmaLinux", fedora = "Fedora",
  }, try(h.os, data.conn3x_host.facts[name].os_id), "") }
  os_family_name = { for name, h in var.hosts : name => { debian = "Debian", redhat = "RedHat" }[local.os_family[name]] }
  # Ansible's distribution_version has a minor version on Debian, which
  # os-release doesn't.
  os_version = { for name, h in var.hosts : name => (
    local.os_distribution[name] == "Debian" && !strcontains(data.conn3x_host.facts[name].os_version, ".")
    ? "${data.conn3x_host.facts[name].os_version}.0" : data.conn3x_host.facts[name].os_version
  ) }
  vars_file = { for name, h in var.hosts : name => "${local.os_family[name]}/${[for f in [
    %s,
  ] : f if contains([%s], f)][0]}" }
}
`, strings.Join(cands, ",\n    "), strings.Join(files, ", "))
}
