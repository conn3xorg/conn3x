// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"
)

// A task with a literal loop of plain values becomes a step with for_each
// over the same values, and {{ item }} becomes item.value. Anything else
// about loops stays for a person.

// itemMark stands in for {{ item }} while a module builds its attributes.
const itemMark = "\x00item.value\x00"

// refMark stands in for an HCL expression, such as var.port, the same way.
func refMark(expr string) string { return "\x00" + expr + "\x00" }

var marks = regexp.MustCompile("\x00([^\x00]*)\x00")

// literalLoop reads loop: [a, b, ...]. It returns the reason when the loop
// isn't a list of plain values written in the playbook.
func literalLoop(n *yaml.Node) ([]string, string) {
	if n.Kind != yaml.SequenceNode {
		return nil, "uses a loop over a variable, which the converter can't translate yet; list the items in the playbook or write for_each by hand"
	}
	items := []string{}
	seen := map[string]bool{}
	for _, e := range n.Content {
		if e.Kind != yaml.ScalarNode {
			return nil, "loops over items with fields such as item.name, which the converter can't translate yet; use a map in for_each by hand"
		}
		if strings.Contains(e.Value, "{{") || seen[e.Value] {
			return nil, "loops over items the converter can't prove are distinct plain values"
		}
		seen[e.Value] = true
		items = append(items, e.Value)
	}
	return items, ""
}

// loopSteps checks a looping task's steps use item.
func loopSteps(used bool) string {
	if !used {
		return "loops but doesn't use item, so each pass would do the same thing"
	}
	return ""
}

// resolveMarks turns marks in the steps' attributes into HCL references.
// A mark anywhere but a plain string attribute stops the task.
func resolveMarks(steps []step) string {
	refused := func(v, key, how string) string {
		what := "a role default"
		if strings.Contains(v, "item.value") { // a mark, raw or as GoString shows it
			what = "item"
		}
		return "uses " + what + " " + how + " " + key + ", which the converter can't translate yet"
	}
	for _, s := range steps {
		for _, b := range s.blocks {
			for _, a := range b.attrs {
				if v := a.val.GoString(); strings.Contains(v, `\x00`) {
					return refused(v, b.name+"."+a.key, "inside")
				}
			}
		}
		for i, a := range s.attrs {
			if a.raw != "" || a.val.IsNull() {
				if strings.Contains(a.raw, "\x00") {
					return refused(a.raw, a.key, "in")
				}
				continue
			}
			if !a.val.Type().Equals(cty.String) {
				if v := a.val.GoString(); strings.Contains(v, `\x00`) {
					return refused(v, a.key, "inside")
				}
				continue
			}
			if v := a.val.AsString(); strings.Contains(v, "\x00") {
				s.attrs[i] = attr{key: a.key, raw: markTemplate(v)}
			}
		}
	}
	return ""
}

// markTemplate writes a string holding marks as HCL: the expression alone,
// or a quoted template with ${expr} in it.
func markTemplate(v string) string {
	if m := marks.FindStringSubmatch(v); m != nil && m[0] == v {
		return m[1]
	}
	var b strings.Builder
	b.WriteString(`"`)
	last := 0
	for _, m := range marks.FindAllStringSubmatchIndex(v, -1) {
		b.WriteString(quoted(v[last:m[0]]))
		b.WriteString("${" + v[m[2]:m[3]] + "}")
		last = m[1]
	}
	b.WriteString(quoted(v[last:]) + `"`)
	return b.String()
}

// quoted escapes s for the inside of an HCL string.
func quoted(s string) string {
	q := string(hclwrite.TokensForValue(cty.StringVal(s)).Bytes())
	return q[1 : len(q)-1]
}
