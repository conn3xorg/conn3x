// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package lsp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/textproto"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBlockPath(t *testing.T) {
	for _, tc := range []struct {
		text string
		want string
	}{
		{"circuit \"web\" {\n  step \"motd\" {\n    file {\n      ", "circuit step file"},
		{"circuit \"web\" {\n  step \"motd\" {\n    ", "circuit step"},
		{"circuit \"web\" {\n  hosts = {\n    ", "circuit {"},
		{"circuit \"web\" {\n  # step {\n  x = \"}\"\n  ", "circuit"},
		{"circuit \"a\" {\n  step \"b\" {\n    file {\n      content = <<EOT\n}\n{\nEOT\n      ", "circuit step file"},
		{"step \"a\" {\n  file {\n    path = \"${var.x}\"\n  }\n  ", "step"},
	} {
		if got := strings.Join(blockPath(tc.text), " "); got != tc.want {
			t.Errorf("%q: %q, want %q", tc.text, got, tc.want)
		}
	}
}

func TestArgsSetAndOffset(t *testing.T) {
	set := argsSet("file {\n  path = \"/x\"\n  content = {\n    mode = 1\n  }\n  ")
	if !set["path"] || !set["content"] || set["mode"] {
		t.Errorf("args set %v", set)
	}
	text := "a\nhé\U0001F600x\n"
	// The emoji is two UTF-16 units: column 3 is after it.
	if got := offset(text, 1, 3); text[got:got+1] != "x" {
		t.Errorf("offset lands on %q", text[got:])
	}
	if got := offset(text, 9, 0); got != len(text) {
		t.Errorf("past the end: %d", got)
	}
}

// client drives a Server over pipes.
type client struct {
	t   *testing.T
	in  io.Writer
	out *textproto.Reader
	id  int
}

func start(t *testing.T, self string) *client {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	s := &Server{Name: "conn3x", Version: "test", Self: self}
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), inR, outW) }()
	t.Cleanup(func() {
		inW.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server didn't stop")
		}
	})
	return &client{t: t, in: inW, out: textproto.NewReader(bufio.NewReader(outR))}
}

func (c *client) write(v map[string]any) {
	v["jsonrpc"] = "2.0"
	b, _ := json.Marshal(v)
	fmt.Fprintf(c.in, "Content-Length: %d\r\n\r\n%s", len(b), b)
}

func (c *client) read() map[string]any {
	c.t.Helper()
	h, err := c.out.ReadMIMEHeader()
	if err != nil {
		c.t.Fatal(err)
	}
	n, _ := strconv.Atoi(h.Get("Content-Length"))
	b := make([]byte, n)
	if _, err := io.ReadFull(c.out.R, b); err != nil {
		c.t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		c.t.Fatal(err)
	}
	return m
}

func (c *client) call(method string, params any) any {
	c.t.Helper()
	c.id++
	c.write(map[string]any{"id": c.id, "method": method, "params": params})
	m := c.read()
	if m["error"] != nil {
		c.t.Fatalf("%s: %v", method, m["error"])
	}
	return m["result"]
}

func (c *client) open(uri, text string) {
	c.write(map[string]any{"method": "textDocument/didOpen", "params": map[string]any{"textDocument": map[string]any{"uri": uri, "text": text}}})
}

func at(uri string, line, char int) map[string]any {
	return map[string]any{"textDocument": map[string]any{"uri": uri}, "position": map[string]any{"line": line, "character": char}}
}

func labels(v any) []string {
	var out []string
	for _, it := range v.([]any) {
		out = append(out, it.(map[string]any)["label"].(string))
	}
	return out
}

func TestCompletionAndHover(t *testing.T) {
	c := start(t, "")
	caps := c.call("initialize", map[string]any{})
	if caps.(map[string]any)["capabilities"].(map[string]any)["hoverProvider"] != true {
		t.Fatalf("capabilities %v", caps)
	}
	uri := "file:///w/main.circuit.hcl"
	text := "circuit \"web\" {\n  step \"motd\" {\n    \n  }\n  step \"conf\" {\n    file {\n      path = \"/etc/motd\"\n      \n    }\n  }\n}\n"
	c.open(uri, text)

	mods := labels(c.call("textDocument/completion", at(uri, 2, 4)))
	if !contains(mods, "file") || !contains(mods, "package") || !contains(mods, "template") {
		t.Fatalf("modules offered: %v", mods)
	}
	args := c.call("textDocument/completion", at(uri, 7, 6)).([]any)
	names := labels(args)
	if contains(names, "path") || !contains(names, "content") || !contains(names, "mode") {
		t.Fatalf("file arguments offered: %v", names)
	}
	if outside := c.call("textDocument/completion", at(uri, 0, 0)); len(outside.([]any)) != 0 {
		t.Errorf("outside a step: %v", outside)
	}

	h := c.call("textDocument/hover", at(uri, 5, 5)).(map[string]any)
	if v := h["contents"].(map[string]any)["value"].(string); !strings.Contains(v, "**file**") || !strings.Contains(v, "docs.conn3x.org/modules/file") {
		t.Errorf("hover on file: %q", v)
	}
	h = c.call("textDocument/hover", at(uri, 6, 7)).(map[string]any)
	if v := h["contents"].(map[string]any)["value"].(string); !strings.Contains(v, "**path**") || !strings.Contains(v, "required") {
		t.Errorf("hover on path: %q", v)
	}
	if got := c.call("textDocument/hover", at(uri, 0, 1)); got != nil {
		t.Errorf("hover on circuit: %v", got)
	}
	if got := c.call("shutdown", nil); got != nil {
		t.Errorf("shutdown: %v", got)
	}
	c.write(map[string]any{"method": "exit"})
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// Saving runs conn3x validate in the file's directory and shows its errors
// on the files they're in; the next save clears what's fixed.
func TestSaveValidates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in for conn3x is a shell script")
	}
	dir := t.TempDir()
	self := filepath.Join(dir, "conn3x")
	result := filepath.Join(dir, "result.json")
	if err := os.WriteFile(self, []byte("#!/bin/sh\ncat "+result+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(s string) {
		if err := os.WriteFile(result, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c := start(t, self)
	c.call("initialize", map[string]any{})
	uri := "file://" + filepath.ToSlash(dir) + "/main.circuit.hcl"
	other := "file://" + filepath.ToSlash(dir) + "/other.tf"
	c.open(uri, "circuit \"web\" {}\n")

	write(`{"diagnostics":[{"severity":"error","summary":"Missing required argument","detail":"hosts is required.","range":{"filename":"main.circuit.hcl","start":{"line":1,"column":17},"end":{"line":1,"column":18}}},{"severity":"warning","summary":"Deprecated","range":{"filename":"other.tf","start":{"line":2,"column":1},"end":{"line":2,"column":4}}}]}`)
	c.write(map[string]any{"method": "textDocument/didSave", "params": map[string]any{"textDocument": map[string]any{"uri": uri}}})
	got := map[string][]any{}
	for range 2 {
		m := c.read()
		p := m["params"].(map[string]any)
		got[p["uri"].(string)] = p["diagnostics"].([]any)
	}
	if d := got[uri]; len(d) != 1 || !strings.Contains(d[0].(map[string]any)["message"].(string), "hosts is required") ||
		d[0].(map[string]any)["range"].(map[string]any)["start"].(map[string]any)["character"].(float64) != 16 {
		t.Errorf("main: %v", d)
	}
	if d := got[other]; len(d) != 1 || d[0].(map[string]any)["severity"].(float64) != 2 {
		t.Errorf("other: %v", d)
	}

	write(`{"diagnostics":[]}`)
	c.write(map[string]any{"method": "textDocument/didSave", "params": map[string]any{"textDocument": map[string]any{"uri": uri}}})
	for range 2 {
		p := c.read()["params"].(map[string]any)
		if len(p["diagnostics"].([]any)) != 0 {
			t.Errorf("%s not cleared: %v", p["uri"], p["diagnostics"])
		}
	}
}
