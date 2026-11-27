// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
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

// readableReason displays references in diagnostic text without leaking the
// converter's internal markers into summaries or TODO comments.
func readableReason(reason string) string {
	return marks.ReplaceAllStringFunc(reason, func(mark string) string {
		return "${" + mark[1:len(mark)-1] + "}"
	})
}

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

// mapLoop reads loop: [{name: a, port: "80"}, ...], a list of maps
// written in the task. A value is plain, as plainValue reads it, or text
// with Jinja in it, which each item's own check proves. ok is false for
// any other loop.
func mapLoop(n *yaml.Node) ([]map[string]string, bool) {
	if n == nil || n.Kind != yaml.SequenceNode || len(n.Content) == 0 || n.Content[0].Kind != yaml.MappingNode {
		return nil, false
	}
	var items []map[string]string
	for _, e := range n.Content {
		if e.Kind != yaml.MappingNode {
			return nil, false
		}
		item := map[string]string{}
		for _, kv := range pairs(e) {
			v, _, why := plainValue(kv[1])
			if why == "a Jinja expression" {
				v, why = kv[1].Value, ""
			}
			if why != "" || !identifier.MatchString(kv[0].Value) {
				return nil, false
			}
			item[kv[0].Value] = v
		}
		items = append(items, item)
	}
	return items, true
}

// markRefs is an item's value with each {{ name }} as the mark the steps
// use for it: a play variable's value, or r.ref(name) for a role default.
func markRefs(v string, vars map[string]string, r *role) string {
	return jinja.ReplaceAllStringFunc(v, func(m string) string {
		name := jinja.FindStringSubmatch(m)[1]
		if val, ok := vars[name]; ok {
			return val
		}
		return refMark(r.ref(name))
	})
}

// withItem is args with each {{ item.field }} in its text replaced by
// that field of it, or the field's default. why says which field it lacks.
func withItem(args map[string]*yaml.Node, it map[string]string) (out map[string]*yaml.Node, why string) {
	var fill func(n *yaml.Node) *yaml.Node
	fill = func(n *yaml.Node) *yaml.Node {
		c := *n
		if n.Kind == yaml.ScalarNode {
			c.Value = itemField.ReplaceAllStringFunc(n.Value, func(m string) string {
				sub := itemField.FindStringSubmatch(m)
				if v, ok := it[sub[1]]; ok {
					return v
				}
				if strings.Contains(m, "default(") {
					return sub[2] + sub[3]
				}
				why = "doesn't have " + sub[1]
				return m
			})
			return &c
		}
		c.Content = make([]*yaml.Node, len(n.Content))
		for i, e := range n.Content {
			c.Content[i] = fill(e)
		}
		return &c
	}
	out = map[string]*yaml.Node{}
	for k, v := range args {
		out[k] = fill(v)
	}
	return out, why
}

// mapLoopKey is the field a written loop over maps is keyed by: name if
// the steps need it and it's written out in every item, else the first
// such field in order. why says why there's none, or two items share it.
func mapLoopKey(items []map[string]string, fields map[string]*string) (key, why string) {
	plain := map[string]*string{}
	for f, d := range fields {
		if d != nil || !slices.ContainsFunc(items, func(it map[string]string) bool { return strings.Contains(it[f], "{{") }) {
			plain[f] = d
		}
	}
	if key = loopKey(plain); key == "" {
		return "", "loops over maps, but no field every item has is written out in each, so there's nothing to tell the steps apart by"
	}
	seen := map[string]bool{}
	for _, it := range items {
		if seen[it[key]] {
			return "", fmt.Sprintf("loops over maps with %s %q twice, and a step runs once per %s; write the task once per item", key, it[key], key)
		}
		seen[it[key]] = true
	}
	return key, ""
}

// mapLoopObject is a written loop over maps as for_each: each item by its
// key field, with the fields the steps read, a missing one at its default.
// Plain values are written as they are; any with Jinja make it an HCL
// expression, each {{ name }} a reference.
func mapLoopObject(items []map[string]string, fields map[string]*string, key string, vars map[string]string, r *role) (cty.Value, string) {
	byKey := map[string]cty.Value{}
	var raw []string
	templated := false
	for _, it := range items {
		obj := map[string]cty.Value{}
		var parts []string
		for _, f := range slices.Sorted(maps.Keys(fields)) {
			v, ok := it[f]
			if !ok {
				v = *fields[f]
			}
			obj[f] = cty.StringVal(v)
			m := markRefs(v, vars, r)
			templated = templated || m != v
			parts = append(parts, f+" = "+markTemplate(m))
		}
		byKey[it[key]] = cty.ObjectVal(obj)
		raw = append(raw, fmt.Sprintf("  \"%s\" = { %s }", quoted(it[key]), strings.Join(parts, ", ")))
	}
	if templated {
		return cty.NilVal, "{\n" + strings.Join(raw, "\n") + "\n}"
	}
	return cty.ObjectVal(byKey), ""
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
			// A list holding facts, and no other marks, is written item by item.
			if a.val.Type().Equals(cty.List(cty.String)) {
				var items []string
				all := ""
				for _, e := range a.val.AsValueSlice() {
					items = append(items, markTemplate(e.AsString()))
					all += e.AsString()
				}
				if strings.Contains(all, "\x00") && !strings.Contains(factWord(all), "\x00") {
					s.attrs[i] = attr{key: a.key, raw: "[" + strings.Join(items, ", ") + "]"}
					continue
				}
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

// hclString is s as an HCL quoted string. Go's %q escapes for Go: it leaves
// ${ and %{ live, so a role's text would run as an expression in the
// circuit, and it writes escapes HCL doesn't have, such as \a and \x00.
func hclString(s string) string {
	return `"` + quoted(s) + `"`
}

// quoted escapes s for the inside of an HCL string.
func quoted(s string) string {
	q := string(hclwrite.TokensForValue(cty.StringVal(s)).Bytes())
	return q[1 : len(q)-1]
}

// sameForItem reports whether steps built with item as a mark are, with
// value in its place, the steps the module built for value itself.
func sameForItem(marked, got []step, value string) bool {
	return sameWith(marked, got, strings.NewReplacer(itemMark, value))
}

// sameWith reports whether steps built with marks are, with put's values
// in their place, the steps the module built for those values.
func sameWith(marked, got []step, repl *strings.Replacer) bool {
	put := func(v cty.Value) cty.Value {
		out, err := cty.Transform(v, func(_ cty.Path, v cty.Value) (cty.Value, error) {
			if v.IsKnown() && !v.IsNull() && v.Type() == cty.String {
				return cty.StringVal(repl.Replace(v.AsString())), nil
			}
			return v, nil
		})
		if err != nil {
			return cty.NilVal
		}
		return out
	}
	same := func(a, b []attr) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i].key != b[i].key || a[i].raw != b[i].raw || a[i].val.IsNull() != b[i].val.IsNull() {
				return false
			}
			if !a[i].val.IsNull() && !put(a[i].val).RawEquals(b[i].val) {
				return false
			}
		}
		return true
	}
	if len(marked) != len(got) {
		return false
	}
	for i := range marked {
		m, g := marked[i], got[i]
		if m.module != g.module || !same(m.attrs, g.attrs) || len(m.blocks) != len(g.blocks) {
			return false
		}
		for j := range m.blocks {
			if m.blocks[j].name != g.blocks[j].name || !same(m.blocks[j].attrs, g.blocks[j].attrs) {
				return false
			}
		}
	}
	return true
}
