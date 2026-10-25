// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"
)

// A task with a literal loop of plain values becomes a step with for_each
// over the same values, and {{ item }} becomes item.value. Anything else
// about loops stays for a person.

// itemMark stands in for {{ item }} while a module builds its attributes.
const itemMark = "\x00item\x00"

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

// loopSteps turns {{ item }} in the steps' attributes into item.value.
func loopSteps(steps []step, used bool) string {
	if !used {
		return "loops but doesn't use item, so each pass would do the same thing"
	}
	for _, s := range steps {
		for i, a := range s.attrs {
			if a.raw != "" || a.val.IsNull() {
				if strings.Contains(a.raw, itemMark) {
					return "uses item in " + a.key + ", which the converter can't translate yet"
				}
				continue
			}
			if !a.val.Type().Equals(cty.String) {
				if strings.Contains(a.val.GoString(), "\\x00item") {
					return "uses item inside " + a.key + ", which the converter can't translate yet"
				}
				continue
			}
			v := a.val.AsString()
			if !strings.Contains(v, itemMark) {
				continue
			}
			s.attrs[i] = attr{key: a.key, raw: itemTemplate(v)}
		}
	}
	return ""
}

// itemTemplate writes a string holding itemMark as HCL: item.value alone,
// or a quoted template with ${item.value} in it.
func itemTemplate(v string) string {
	if v == itemMark {
		return "item.value"
	}
	parts := strings.Split(v, itemMark)
	for i, p := range parts {
		q := string(hclwrite.TokensForValue(cty.StringVal(p)).Bytes())
		parts[i] = q[1 : len(q)-1]
	}
	return `"` + strings.Join(parts, "${item.value}") + `"`
}
