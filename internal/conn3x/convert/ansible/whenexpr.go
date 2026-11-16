// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// whenAtom is a role task's one-condition when as a step's when: a
// default, a probe, an installed package, the distribution or a list's
// length. "" for any other.
func (r *role) whenAtom(cond string) string {
	n := &yaml.Node{Kind: yaml.ScalarNode, Value: cond}
	for _, f := range []func(*yaml.Node) string{r.boolWhen, packagesWhen, distributionWhen, r.lengthWhen} {
		if e := f(n); e != "" {
			return e
		}
	}
	return ""
}

// whenExpr is a role task's when as a step's when, as whenAtom reads it or
// built from those with and, or, not and parentheses, which bind as they
// do in Jinja. A test of the family alone is left to familyWhen, which
// also narrows what the task converts for; inside and or or it reads as
// local.os_family. "" when any part is something else.
func (r *role) whenExpr(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	cond := strings.Join(strings.Fields(n.Value), " ")
	if e := r.whenAtom(cond); e != "" {
		return e
	}
	if _, _, family := familyWhen(n); family {
		return ""
	}
	return r.combined(cond)
}

func (r *role) combined(cond string) string {
	cond = strings.TrimSpace(cond)
	for _, op := range []struct{ jinja, hcl string }{{" or ", " || "}, {" and ", " && "}} {
		if parts := splitTop(cond, op.jinja); len(parts) > 1 {
			out := make([]string, len(parts))
			for i, p := range parts {
				if out[i] = r.combined(p); out[i] == "" {
					return ""
				}
				out[i] = "(" + out[i] + ")"
			}
			return strings.Join(out, op.hcl)
		}
	}
	if inner, ok := unwrap(cond); ok {
		return r.combined(inner)
	}
	if rest, ok := strings.CutPrefix(cond, "not "); ok {
		if e := r.combined(rest); e != "" {
			return "!(" + e + ")"
		}
		return ""
	}
	if e := r.whenAtom(cond); e != "" {
		return e
	}
	if m := familyCompare.FindStringSubmatch(cond); m != nil {
		for _, f := range osFamilies {
			if f.ansible == m[2] {
				return fmt.Sprintf(`local.os_family[each.key] %s "%s"`, m[1], f.conn3x)
			}
		}
	}
	return ""
}

// splitTop splits s at sep where sep is outside quotes and parentheses.
func splitTop(s, sep string) []string {
	var parts []string
	depth, quote, start := 0, byte(0), 0
	for i := 0; i < len(s); i++ {
		switch ch := s[i]; {
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '\'' || ch == '"':
			quote = ch
		case ch == '(':
			depth++
		case ch == ')':
			depth--
		case depth == 0 && strings.HasPrefix(s[i:], sep):
			parts = append(parts, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	return append(parts, s[start:])
}

// unwrap takes off parentheses that wrap all of s.
func unwrap(s string) (string, bool) {
	if !strings.HasPrefix(s, "(") || !strings.HasSuffix(s, ")") {
		return "", false
	}
	depth := 0
	for i := 0; i < len(s)-1; i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		}
		if depth == 0 {
			return "", false // the first ( closes before the end
		}
	}
	return s[1 : len(s)-1], true
}

var lengthWhenRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*) ?\| ?length ?(==|!=|>=|<=|>|<) ?(\d+)$`)

// lengthWhen reads a list or text default's length compared to a number,
// as security_sudoers_passwordless | length > 0. A list becomes a
// variable for it once the task converts, as for a loop over one; see
// whenListRe. "" for any other when.
func (r *role) lengthWhen(n *yaml.Node) string {
	m := lengthWhenRe.FindStringSubmatch(strings.Join(strings.Fields(n.Value), " "))
	if m == nil {
		return ""
	}
	name := m[1]
	_, isList := r.lists[name]
	d := r.defaults[name]
	list := isList && r.maps[name] == nil || r.mapFields[name] != nil
	text := d != nil && !d.boolean && !d.number
	if !list && !text {
		return ""
	}
	return fmt.Sprintf("length(var.%s) %s %s", name, m[2], m[3])
}

// whenListRe finds the lists a converted step's when reads the length of.
var whenListRe = regexp.MustCompile(`length\(var\.([A-Za-z_][A-Za-z0-9_]*)\)`)
