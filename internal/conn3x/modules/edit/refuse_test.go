// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package edit

import (
	"strings"
	"testing"
)

// Each Apply refuses what its Validate refuses, before touching content,
// and says why.
func TestApplyRefusesInvalidEdits(t *testing.T) {
	const content = "keep me\n"
	for want, apply := range map[string]func() (string, error){
		"line or regexp is required": func() (string, error) { return ApplyLine(content, Line{State: Absent}) },
		"insert_after or insert_before": func() (string, error) {
			return ApplyLine(content, Line{Line: "x", InsertAfter: "a", InsertBefore: "b"})
		},
		"insert_before: error parsing regexp": func() (string, error) { return ApplyLine(content, Line{Line: "x", InsertBefore: "("}) },
		"set insert_after or insert_before, not both": func() (string, error) {
			return ApplyBlock(content, Block{InsertAfter: "a", InsertBefore: "b"})
		},
		"insert_after: error parsing regexp":   func() (string, error) { return ApplyBlock(content, Block{InsertAfter: "["}) },
		`state must be "present" or "absent"`:  func() (string, error) { return ApplyBlock(content, Block{State: "gone"}) },
		"option is required":                   func() (string, error) { return ApplyINI(content, INI{State: Present}) },
		"domain \"\" must be one word":         func() (string, error) { return ApplyLimit(content, Limit{State: Present}) },
		"regexp is required":                   func() (string, error) { return ApplyReplace(content, Replace{}) },
		"path must name a value":               func() (string, error) { return ApplyJSONValue(`{}`, JSONValue{}) },
		"isn't JSON; write it with jsonencode": func() (string, error) { return ApplyJSONValue(`{}`, JSONValue{Path: "a", Value: "x", State: Present}) },
		"must start at the root with one /":    func() (string, error) { return ApplyXMLValue("<a/>", XMLValue{XPath: "a"}) },
		`"1x" isn't an attribute name`:         func() (string, error) { return ApplyXMLValue("<a/>", XMLValue{XPath: "/a/@1x"}) },
		"names no element":                     func() (string, error) { return ApplyXMLValue("<a/>", XMLValue{XPath: "/@id"}) },
		"picks the element by @id and sets it": func() (string, error) {
			return ApplyXMLValue("<a/>", XMLValue{XPath: "/a[@id='1']/@id", State: Present})
		},
	} {
		got, err := apply()
		if err == nil || !strings.Contains(err.Error(), want) || got != "" {
			t.Errorf("%s: got %q, %v", want, got, err)
		}
	}
}

// An explicit present is the default, and absent takes a line out.
func TestExplicitStates(t *testing.T) {
	if got, err := ApplyLine("a\n", Line{Line: "b", State: Present}); err != nil || got != "a\nb\n" {
		t.Errorf("line present: %q, %v", got, err)
	}
	if got, err := ApplyBlock("a\n", Block{Content: "x", State: Present}); err != nil || !strings.Contains(got, "x\n") {
		t.Errorf("block present: %q, %v", got, err)
	}
	// A block that isn't there and shouldn't be leaves the file alone.
	if got, err := ApplyBlock("a", Block{State: Absent}); err != nil || got != "a" {
		t.Errorf("block absent: %q, %v", got, err)
	}
	if got, err := ApplyINI("", INI{Option: "k", Value: "v", State: Present}); err != nil || got != "k = v\n" {
		t.Errorf("ini present: %q, %v", got, err)
	}
	if got, err := ApplyLimit("", Limit{Domain: "*", Type: "soft", Item: "nofile", Value: "1024", State: Present}); err != nil || !strings.Contains(got, "nofile") {
		t.Errorf("limit present: %q, %v", got, err)
	}
	if got, err := ApplyJSONValue(`{"a": 1}`, JSONValue{Path: "a", Value: "2", State: Present}); err != nil || got != `{"a": 2}` {
		t.Errorf("json present: %q, %v", got, err)
	}
	if got, err := ApplyXMLValue("<a><b>1</b></a>", XMLValue{XPath: "/a/b", Value: "2", State: Present}); err != nil || got != "<a><b>2</b></a>" {
		t.Errorf("xml present: %q, %v", got, err)
	}
	if got, err := ApplyXMLValue("<a id='1'/>", XMLValue{XPath: "/a[@id='1']/@id", State: Absent}); err != nil || got != "<a/>" {
		t.Errorf("xml absent attribute it picks by: %q, %v", got, err)
	}
	if got := join(nil, true); got != "" {
		t.Errorf("join of nothing: %q", got)
	}
	if got := join([]string{"a"}, false); got != "a" {
		t.Errorf("join without a final newline: %q", got)
	}
}
