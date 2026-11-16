// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestLiteralLoop(t *testing.T) {
	for src, want := range map[string]string{
		"[a, a]":       "can't prove are distinct plain values",
		"['{{ x }}']":  "can't prove are distinct plain values",
		"'{{ list }}'": "uses a loop over a variable",
		"[{a: 1}]":     "loops over items with fields",
	} {
		if _, why := literalLoop(parseTask(t, src)); !strings.Contains(why, want) {
			t.Errorf("%s: %q, want %q", src, why, want)
		}
	}
	if items, why := literalLoop(parseTask(t, "[a, b]")); why != "" || strings.Join(items, ",") != "a,b" {
		t.Errorf("got %v, %s", items, why)
	}
}

// A mark anywhere but in a plain string attribute stops the task, naming
// where; in a string, it becomes a reference.
func TestResolveMarks(t *testing.T) {
	item := cty.StringVal("/srv/" + itemMark)
	def := cty.StringVal(refMark("var.port"))
	for name, c := range map[string]struct {
		s    step
		want string
	}{
		"in a block":    {step{blocks: []stepBlock{{name: "entry", attrs: []attr{{key: "principal", val: item}}}}}, "uses item inside entry.principal"},
		"in raw":        {step{attrs: []attr{{key: "content", raw: "file(" + refMark("var.f") + ")"}}}, "uses a role default in content"},
		"in a list":     {step{attrs: []attr{{key: "groups", val: cty.ListVal([]cty.Value{def})}}}, "uses a role default inside groups"},
		"in a list too": {step{attrs: []attr{{key: "names", val: cty.ListVal([]cty.Value{item})}}}, "uses item inside names"},
	} {
		if why := resolveMarks([]step{c.s}); why != c.want+", which the converter can't translate yet" {
			t.Errorf("%s: %q", name, why)
		}
	}
	s := step{attrs: []attr{{key: "path", val: item}, {key: "port", val: def}, {key: "n", val: cty.NumberIntVal(1)}, {key: "x", val: cty.NullVal(cty.String)}, {key: "raw", raw: "var.ok"}}}
	if why := resolveMarks([]step{s}); why != "" {
		t.Fatal(why)
	}
	if s.attrs[0].raw != `"/srv/${item.value}"` || s.attrs[1].raw != "var.port" || s.attrs[4].raw != "var.ok" {
		t.Errorf("got %+v", s.attrs)
	}
}

func TestSameForItem(t *testing.T) {
	marked := []step{{module: "user", attrs: []attr{{key: "name", val: cty.StringVal(itemMark)}, {key: "x", val: cty.NullVal(cty.String)}}, blocks: []stepBlock{{name: "b", attrs: []attr{{key: "k", val: cty.StringVal("v")}}}}}}
	got := []step{{module: "user", attrs: []attr{{key: "name", val: cty.StringVal("alice")}, {key: "x", val: cty.NullVal(cty.String)}}, blocks: []stepBlock{{name: "b", attrs: []attr{{key: "k", val: cty.StringVal("v")}}}}}}
	if !sameForItem(marked, got, "alice") {
		t.Fatal("the same steps differ")
	}
	for name, change := range map[string]func(s *step){
		"value":       func(s *step) { s.attrs[0].val = cty.StringVal("bob") },
		"module":      func(s *step) { s.module = "group" },
		"attrs":       func(s *step) { s.attrs = s.attrs[:1] },
		"key":         func(s *step) { s.attrs[1].key = "y" },
		"null":        func(s *step) { s.attrs[1].val = cty.StringVal("") },
		"blocks":      func(s *step) { s.blocks = nil },
		"block name":  func(s *step) { s.blocks[0].name = "c" },
		"block attrs": func(s *step) { s.blocks[0].attrs[0].val = cty.StringVal("w") },
	} {
		g := got[0]
		g.attrs = append([]attr{}, g.attrs...)
		g.blocks = []stepBlock{{name: "b", attrs: []attr{{key: "k", val: cty.StringVal("v")}}}}
		change(&g)
		if sameForItem(marked, []step{g}, "alice") {
			t.Errorf("%s: a different step is the same", name)
		}
	}
	if sameForItem(marked, nil, "alice") {
		t.Error("no steps are the same as one")
	}
}
