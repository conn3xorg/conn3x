// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package edit

import "testing"

func TestApplyJSONValue(t *testing.T) {
	doc := "{\n  \"name\": \"app\",\n  \"server\": {\n    \"port\": 8080,\n    \"tls\": false\n  },\n  \"hosts\": [\"a\", {\"n\": 1}]\n}\n"
	for _, c := range []struct {
		name string
		in   string
		c    JSONValue
		want string
	}{
		{"replace a number", doc, JSONValue{Path: "server.port", Value: "9090"},
			"{\n  \"name\": \"app\",\n  \"server\": {\n    \"port\": 9090,\n    \"tls\": false\n  },\n  \"hosts\": [\"a\", {\"n\": 1}]\n}\n"},
		{"equal however written", doc, JSONValue{Path: "server.port", Value: "8080.0"}, doc},
		{"add a key, indented as its siblings", doc, JSONValue{Path: "server.host", Value: `"0.0.0.0"`},
			"{\n  \"name\": \"app\",\n  \"server\": {\n    \"port\": 8080,\n    \"tls\": false,\n    \"host\": \"0.0.0.0\"\n  },\n  \"hosts\": [\"a\", {\"n\": 1}]\n}\n"},
		{"add a nested path", `{"a": 1}`, JSONValue{Path: "log.level", Value: `"info"`}, `{"a": 1, "log": {"level":"info"}}`},
		{"into an array element", doc, JSONValue{Path: "hosts[1].n", Value: "2"},
			"{\n  \"name\": \"app\",\n  \"server\": {\n    \"port\": 8080,\n    \"tls\": false\n  },\n  \"hosts\": [\"a\", {\"n\": 2}]\n}\n"},
		{"an object value, compacted", `{"a": 1}`, JSONValue{Path: "a", Value: "{\n \"x\": [1, 2]\n}"}, `{"a": {"x":[1,2]}}`},
		{"drop a middle key", doc, JSONValue{Path: "server.port", State: Absent},
			"{\n  \"name\": \"app\",\n  \"server\": {\n    \"tls\": false\n  },\n  \"hosts\": [\"a\", {\"n\": 1}]\n}\n"},
		{"drop the last key", doc, JSONValue{Path: "server.tls", State: Absent},
			"{\n  \"name\": \"app\",\n  \"server\": {\n    \"port\": 8080\n  },\n  \"hosts\": [\"a\", {\"n\": 1}]\n}\n"},
		{"drop on one line", `{"a": 1, "b": 2, "c": 3}`, JSONValue{Path: "b", State: Absent}, `{"a": 1, "c": 3}`},
		{"drop the only key", `{"a": 1}`, JSONValue{Path: "a", State: Absent}, `{}`},
		{"absent and missing", doc, JSONValue{Path: "nope.x", State: Absent}, doc},
		{"empty file", "", JSONValue{Path: "a", Value: "true"}, "{\"a\": true}\n"},
		{"escaped key", `{"a\"b": 1}`, JSONValue{Path: `a"b`, Value: "2"}, `{"a\"b": 2}`},
	} {
		got, err := ApplyJSONValue(c.in, c.c)
		if err != nil || got != c.want {
			t.Errorf("%s:\n got %q, %v\nwant %q", c.name, got, err, c.want)
		}
		if err == nil {
			again, _ := ApplyJSONValue(got, c.c)
			if again != got {
				t.Errorf("%s: not idempotent: %q", c.name, again)
			}
		}
	}
	for name, c := range map[string]JSONValue{
		"not JSON":       {Path: "a", Value: "info"},
		"bad path":       {Path: "a..b", Value: "1"},
		"index too far":  {Path: "hosts[5]", Value: "1"},
		"key on array":   {Path: "hosts.x", Value: "1"},
		"drop element":   {Path: "hosts[0]", State: Absent},
		"bad state":      {Path: "a", Value: "1", State: "gone"},
		"make an array":  {Path: "new[0]", Value: "1"},
		"not JSON input": {Path: "a", Value: "1"},
	} {
		in := doc
		if name == "not JSON input" {
			in = "{a: 1}"
		}
		if _, err := ApplyJSONValue(in, c); err == nil {
			t.Errorf("%s passed", name)
		}
	}
}
