// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
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
	majorName        = regexp.MustCompile(`^(?:` + majorFact + `|ansible_(?:facts\.distribution_version|facts\[["']distribution_version["']\]|distribution_version)\.split\(["']\.["']\)\[0\])$`)
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
// in family fam. osVersions lists only major releases for Debian and the
// Red Hat family, whose distribution_version has a minor version too, so
// there it's a pattern: the converter can't list every minor release.
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

// firstFoundEntries reads a with_first_found list: its names as templates,
// and whether skip is set. false when the list isn't plain enough to tell.
func firstFoundEntries(n *yaml.Node) ([][]namePart, bool, bool) {
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
				return nil, false, false
			}
		}
	} else if !add(n) {
		return nil, false, false
	}
	var templates [][]namePart
	for _, e := range entries {
		segs, ok := nameTemplate(e)
		if !ok {
			return nil, false, false
		}
		templates = append(templates, segs)
	}
	return templates, skip, true
}

// firstFile is the first template that names an existing file under vars/
// for release v of distribution d in family fam, or "" for none. false when
// a name the converter can't fill in exactly could match a file.
func (c *converter) firstFile(templates [][]namePart, fam, d, v string) (string, bool) {
	for _, segs := range templates {
		name, pattern := fill(segs, fam, d, v)
		if pattern {
			if matches, _ := filepath.Glob(c.path("vars/" + name)); len(matches) > 0 {
				return "", false // whether it loads depends on a minor release the converter doesn't list
			}
			continue
		}
		if st, err := os.Stat(c.path("vars/" + name)); err == nil && !st.IsDir() {
			return name, true
		}
	}
	return "", true
}

// versionBlocks is what a circuit whose values come from more than one
// vars file per family needs on top of familyBlocks: the files each host
// loads, worked out at plan from its facts as Ansible's includes would, as
// the key its values are looked up by.
func (c *converter) versionBlocks(incs []varsInclude) string {
	var files []string
	if entries, err := os.ReadDir(c.path("vars")); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				files = append(files, hclString(e.Name()))
			}
		}
	}
	var picks []string
	for _, inc := range incs {
		var cands []string
		for _, segs := range inc.templates {
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
		pick := fmt.Sprintf("try([for f in [%s] : f if contains(local.vars_files, f)][0], \"\")", strings.Join(cands, ", "))
		if len(inc.when) > 0 {
			var tests []string
			for _, t := range inc.when {
				tests = append(tests, t.hcl())
			}
			pick = fmt.Sprintf("%s ? %s : \"\"", strings.Join(tests, " && "), pick)
		}
		picks = append(picks, pick)
	}
	return fmt.Sprintf(`
# Which of the role's vars files each host loads, worked out from its facts
# as the role's include_vars tasks pick them. Its values are looked up by
# that list. A host whose list the converter didn't read values for, such as
# one on an older release, or one where an include would find no file and
# stop the play, fails at plan where a step looks a value up.
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
  vars_files = [%s]
  vars_file = { for name, h in var.hosts : name => "${local.os_family[name]}/${join("+", compact([
    %s,
  ]))}" }
}
`, strings.Join(files, ", "), strings.Join(picks, ",\n    "))
}
