// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"
)

func TestJinjaLiteralWords(t *testing.T) {
	vals, why := (&jinjaLit{s: `"dq", True, false, none, -2)`}).args()
	if why != "" || len(vals) != 5 {
		t.Fatalf("%v, %s", vals, why)
	}
	if vals[0].AsString() != "dq" || !vals[1].True() || vals[2].True() || !vals[3].IsNull() || vals[4].AsBigFloat().String() != "-2" {
		t.Errorf("got %#v", vals)
	}
}

func TestJSONPatchEdits(t *testing.T) {
	s := cty.StringVal
	for name, c := range map[string]struct {
		args []cty.Value
		want string
	}{
		"one argument":    {[]cty.Value{s("add")}, "arguments other than an operation, a path and a value"},
		"path not text":   {[]cty.Value{s("add"), cty.True, s("x")}, "arguments other than an operation"},
		"add, no value":   {[]cty.Value{s("add"), s("/a")}, `calls json_patch("add") without a value`},
		"remove, a value": {[]cty.Value{s("remove"), s("/a"), s("x")}, "calls json_patch('remove') with a value"},
		"top-level array": {[]cty.Value{s("replace"), s("/0"), s("x")}, "in a document that's an array"},
		"root":            {[]cty.Value{s("remove"), s("/")}, "isn't a key in the document"},
	} {
		if _, why := jsonPatchEdit(c.args); !strings.Contains(why, c.want) {
			t.Errorf("%s: %q, want %q", name, why, c.want)
		}
	}
	if e, why := jsonPatchEdit([]cty.Value{s("replace"), s("/a/2/~0b"), s("x")}); why != "" || e.key != "a[2].~b" {
		t.Errorf("replace in an array: %+v, %s", e, why)
	}
}

// Only a slurp that does nothing else, of a fixed absolute path, pairs
// with the copy after it.
func TestSlurpOf(t *testing.T) {
	for task, want := range map[string]string{
		"slurp: { src: /etc/a.json }\nregister: r":             "/etc/a.json r",
		"slurp: { path: /etc/a.json }\nregister: r\ntags: [x]": "/etc/a.json r",
		"slurp: { src: /etc/a.json }\nwhen: x":                 " ",
		"slurp: { src: /etc/a.json, other: 1 }":                " ",
		"slurp: { src: etc/a.json }":                           " ",
		"slurp: { src: '/{{ d }}/a.json' }":                    " ",
		"slurp: {}":                                            " ",
		"copy: { dest: /a, content: x }":                       " ",
	} {
		src, reg := slurpOf(parseTask(t, task))
		if got := src + " " + reg; got != want {
			t.Errorf("%s: %q, want %q", task, got, want)
		}
	}
}

// parseTask reads one task written as YAML.
func parseTask(t *testing.T, src string) *yaml.Node {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Content[0]
}
