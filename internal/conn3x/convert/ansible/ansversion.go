// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"cmp"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ansibleCoreFloor is the oldest ansible-core a role's whens are read
// against. Ansible sets ansible_version.full to the version of
// ansible-core running the play (CLI.version_info), never to anything
// about the host, so for a circuit, which has no Ansible, a test of it is
// a constant. It reads as true or false only when every ansible-core at
// or above the floor gives the same answer.
const ansibleCoreFloor = "2.16"

// versionTest matches ansible_version.full tested by version, or its old
// name version_compare, against a literal, with an operator
// version_compare takes, eq when left out.
var versionTest = regexp.MustCompile(`^ansible_version(?:\.full|\[["']full["']\]) is (not )?version(?:_compare)?\(["'](\d+(?:\.\d+)*)["'](?:, ?["'](==|=|eq|<|lt|<=|le|>|gt|>=|ge|!=|<>|ne)["'])?\)$`)

const (
	versionReason      = "tests ansible_version, the version of Ansible running the play, in a way the converter can't read as true or false for every ansible-core from " + ansibleCoreFloor + " on"
	versionFalseReason = "tests ansible_version, the version of Ansible running the play, and the test is false on every ansible-core from " + ansibleCoreFloor + " on, so it would never run"
)

// dropAnsibleVersion reads the tests of ansible_version in a task's when
// as every ansible-core from ansibleCoreFloor does: a true one drops out,
// and a false one means the task never runs, which it returns
// versionFalseReason for. What's left of a when as a and b splits into a
// list, which Ansible ANDs too. It returns versionReason when a test
// stays unread.
func dropAnsibleVersion(t map[string]*yaml.Node) string {
	w := deref(t["when"])
	if w == nil {
		return ""
	}
	conds := []*yaml.Node{w}
	if w.Kind == yaml.SequenceNode {
		conds = w.Content
	}
	var kept []*yaml.Node
	changed := false
	for _, c := range conds {
		if c.Kind != yaml.ScalarNode || !strings.Contains(c.Value, "ansible_version") {
			kept = append(kept, c)
			continue
		}
		changed = true
		e, v := foldVersion(strings.Join(strings.Fields(c.Value), " "))
		switch {
		case v < 0:
			return versionFalseReason
		case v > 0:
			continue
		case strings.Contains(e, "ansible_version"):
			return versionReason
		}
		for _, p := range splitTop(e, " and ") {
			kept = append(kept, &yaml.Node{Kind: yaml.ScalarNode, Value: strings.TrimSpace(p), Line: c.Line, Column: c.Column})
		}
	}
	switch {
	case !changed:
	case len(kept) == 0:
		delete(t, "when")
	case len(kept) == 1:
		t["when"] = kept[0]
	default:
		t["when"] = &yaml.Node{Kind: yaml.SequenceNode, Content: kept}
	}
	return ""
}

// dropRunConstants reads what a task's when tests about the Ansible run,
// check mode and then ansible_version, as dropCheckMode and
// dropAnsibleVersion do, and returns why the task stays, if it does. A
// role whose when read ansible_version says so in its README.
func (c *converter) dropRunConstants(t map[string]*yaml.Node) string {
	if why := dropCheckMode(t); why != "" {
		return why
	}
	before := t["when"]
	why := dropAnsibleVersion(t)
	if why == "" && t["when"] != before && c.role != nil {
		c.role.readsVersion = true
	}
	return why
}

// foldVersion reads the ansible_version tests in cond through and, or,
// not and parentheses, which bind as they do in Jinja. v is 1 when cond
// is true, -1 when false, else 0 with e what's left of cond.
func foldVersion(cond string) (e string, v int) {
	cond = strings.TrimSpace(cond)
	for _, op := range []string{" or ", " and "} {
		parts := splitTop(cond, op)
		if len(parts) < 2 {
			continue
		}
		decides := 1 // a true part decides an or, a false one an and
		if op == " and " {
			decides = -1
		}
		var left []string
		for _, p := range parts {
			pe, pv := foldVersion(p)
			if pv == decides {
				return "", decides
			}
			if pv == 0 {
				left = append(left, pe)
			}
		}
		if len(left) == 0 {
			return "", -decides
		}
		return strings.Join(left, op), 0
	}
	if inner, ok := unwrap(cond); ok {
		e, v := foldVersion(inner)
		if v == 0 && (len(splitTop(e, " or ")) > 1 || len(splitTop(e, " and ")) > 1) {
			e = "(" + e + ")"
		}
		return e, v
	}
	if rest, ok := strings.CutPrefix(cond, "not "); ok {
		e, v := foldVersion(rest)
		if v == 0 {
			e = "not " + e
		}
		return e, -v
	}
	m := versionTest.FindStringSubmatch(cond)
	if m == nil {
		return cond, 0
	}
	v = versionFrom(compareVersions(ansibleCoreFloor, m[2]), m[3])
	if m[1] != "" {
		v = -v
	}
	if v != 0 {
		cond = ""
	}
	return cond, v
}

// versionFrom is what version_compare's op gives for every version at or
// above a floor that compares to the literal as c: 1 true, -1 false, 0
// when versions from the floor on differ.
func versionFrom(c int, op string) int {
	switch op {
	case ">=", "ge":
		if c >= 0 {
			return 1
		}
	case ">", "gt":
		if c > 0 {
			return 1
		}
	case "<", "lt":
		if c >= 0 {
			return -1
		}
	case "<=", "le":
		if c > 0 {
			return -1
		}
	case "!=", "<>", "ne":
		if c > 0 {
			return 1
		}
	default: // ==, =, eq or none
		if c > 0 {
			return -1
		}
	}
	return 0
}

// compareVersions compares dotted numbers as Python compares the lists
// LooseVersion splits them into: part by part, and a prefix is smaller.
func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, _ := strconv.Atoi(as[i])
		y, _ := strconv.Atoi(bs[i])
		if x != y {
			return cmp.Compare(x, y)
		}
	}
	return cmp.Compare(len(as), len(bs))
}
