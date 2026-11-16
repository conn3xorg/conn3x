// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// exchange sends lines to a server with Tools and returns its responses by id.
func exchange(t *testing.T, lines ...string) map[string]map[string]any {
	t.Helper()
	s := &Server{Name: "conn3x", Version: "test", Tools: Tools(Options{Self: "conn3x", Root: "/"})}
	var out bytes.Buffer
	if err := s.Serve(context.Background(), strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]any{}
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("response %q: %v", l, err)
		}
		id, _ := json.Marshal(m["id"])
		got[string(id)] = m
	}
	return got
}

func TestProtocol(t *testing.T) {
	got := exchange(t,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":4,"method":"resources/list"}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope"}}`,
		`not json`,
		`{"jsonrpc":"2.0","id":6,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`,
	)
	if len(got) != 7 { // the notification gets no response
		t.Fatalf("got %d responses: %v", len(got), got)
	}
	init := got["1"]["result"].(map[string]any)
	if init["protocolVersion"] != "2025-03-26" || init["serverInfo"].(map[string]any)["name"] != "conn3x" {
		t.Errorf("initialize = %v", init)
	}
	if v := got["6"]["result"].(map[string]any)["protocolVersion"]; v != protocolVersions[0] {
		t.Errorf("an unknown version should get our newest, got %v", v)
	}
	tools := got["3"]["result"].(map[string]any)["tools"].([]any)
	var names []string
	for _, tl := range tools {
		m := tl.(map[string]any)
		names = append(names, m["name"].(string))
		if m["inputSchema"].(map[string]any)["type"] != "object" {
			t.Errorf("%s has no object input schema", m["name"])
		}
	}
	if strings.Join(names, ",") != "search_modules,module_docs,search_circuits,validate,lint,summarise_plan" {
		t.Errorf("tools = %v", names)
	}
	if got["4"]["error"].(map[string]any)["code"].(float64) != methodNotFound {
		t.Errorf("resources/list = %v", got["4"])
	}
	if got["5"]["error"].(map[string]any)["code"].(float64) != invalidParams {
		t.Errorf("unknown tool = %v", got["5"])
	}
	if got["null"]["error"].(map[string]any)["code"].(float64) != parseError {
		t.Errorf("not json = %v", got["null"])
	}
}

// A tool's result and its failure both come back as content; only a
// request the server can't make sense of is a protocol error.
func TestToolsCall(t *testing.T) {
	s := &Server{Name: "conn3x", Version: "test", Tools: []Tool{
		{Name: "echo", Run: func(_ context.Context, args json.RawMessage) (any, error) {
			var m map[string]any
			return m, json.Unmarshal(args, &m)
		}},
		{Name: "fail", Run: func(context.Context, json.RawMessage) (any, error) { return nil, errors.New("no circuit here") }},
		{Name: "odd", Run: func(context.Context, json.RawMessage) (any, error) { return []any{make(chan int)}, nil }},
	}}
	var out bytes.Buffer
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"dir":"web"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fail"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"odd"}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{}}`,
		``,
		`{"jsonrpc":"1.0","id":6,"method":"ping"}`,
		`{"jsonrpc":"2.0","method":""}`,
	}, "\n") + "\n"
	if err := s.Serve(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`{"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"{\n  \"dir\": \"web\"\n}","type":"text"}],"isError":false,"structuredContent":{"dir":"web"}}}`,
		// No arguments are an empty object.
		`{"jsonrpc":"2.0","id":2,"result":{"content":[{"text":"{}","type":"text"}],"isError":false,"structuredContent":{}}}`,
		`{"jsonrpc":"2.0","id":3,"result":{"content":[{"text":"{\n  \"error\": \"no circuit here\"\n}","type":"text"}],"isError":true,"structuredContent":{"error":"no circuit here"}}}`,
		`{"jsonrpc":"2.0","id":4,"result":{"content":[{"text":"json: unsupported type: chan int","type":"text"}],"isError":true}}`,
		`{"jsonrpc":"2.0","id":5,"error":{"code":-32602,"message":"tools/call needs a tool name"}}`,
		`{"jsonrpc":"2.0","id":6,"error":{"code":-32600,"message":"not a JSON-RPC 2.0 request"}}`,
	}
	if got := strings.Split(strings.TrimSpace(out.String()), "\n"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Serve(ctx, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), &out); !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled serve = %v", err)
	}
}

func call(t *testing.T, tool string, args any) (map[string]any, bool) {
	t.Helper()
	return callWith(t, Options{Self: "conn3x", Root: "/"}, tool, args)
}

func callWith(t *testing.T, o Options, tool string, args any) (map[string]any, bool) {
	t.Helper()
	for _, tl := range Tools(o) {
		if tl.Name != tool {
			continue
		}
		raw, _ := json.Marshal(args)
		out, err := tl.Run(context.Background(), raw)
		if err != nil {
			return map[string]any{"error": err.Error()}, true
		}
		b, _ := json.Marshal(out)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return m, false
	}
	t.Fatalf("no tool %s", tool)
	return nil, false
}

func TestModules(t *testing.T) {
	res, _ := call(t, "search_modules", map[string]string{"query": "cron"})
	if !strings.Contains(mustJSON(res), `"module":"cron"`) {
		t.Errorf("search for cron = %v", res)
	}
	all, _ := call(t, "search_modules", map[string]string{})
	if n := all["count"].(float64); n < 30 || !strings.Contains(mustJSON(all), `"module":"template"`) {
		t.Errorf("listing every module gave %v modules", n)
	}
	doc, isErr := call(t, "module_docs", map[string]string{"module": "file"})
	if isErr || !strings.Contains(mustJSON(doc), `"name":"path"`) || !strings.Contains(mustJSON(doc), `"required":true`) || strings.Contains(mustJSON(doc), `"name":"ssh"`) {
		t.Errorf("file docs = %v", doc)
	}
	tpl, _ := call(t, "module_docs", map[string]string{"module": "template"})
	if !strings.Contains(mustJSON(tpl), `"name":"source","required":true`) {
		t.Errorf("template docs = %v", tpl)
	}
	if res, isErr := call(t, "module_docs", map[string]string{"module": "nope"}); !isErr || !strings.Contains(res["error"].(string), "search_modules") {
		t.Errorf("unknown module = %v", res)
	}
	if _, isErr := call(t, "module_docs", map[string]any{"module": "file", "extra": 1}); !isErr {
		t.Error("an unknown argument should be refused")
	}
}

func TestSearchCircuits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"format_version":"1","circuits":[
			{"name":"nginx","description":"A web server","repo_url":"https://github.com/conn3xorg/circuit-nginx","version":"v1.2.0","category":"web","tags":["http"],"grade":"A","passing":true,"page":"https://conn3x.org/circuits/nginx"},
			{"name":"postgres","description":"A database","repo_url":"x","version":"v2.0.0","category":"data","tags":["sql"],"grade":"B","passing":true,"page":"y"}]}`))
	}))
	defer srv.Close()
	saved := CatalogueURL
	defer func() { CatalogueURL = saved }()
	CatalogueURL = srv.URL
	res, isErr := call(t, "search_circuits", map[string]string{"query": "sql"})
	if isErr || res["count"].(float64) != 1 || !strings.Contains(mustJSON(res), `"name":"postgres"`) {
		t.Errorf("search sql = %v", res)
	}
	CatalogueURL = srv.URL + "/missing"
	srv.Config.Handler = http.NotFoundHandler()
	if res, isErr := call(t, "search_circuits", map[string]string{}); !isErr || !strings.Contains(res["error"].(string), "404") {
		t.Errorf("a missing catalogue = %v", res)
	}
	CatalogueURL = "http://127.0.0.1:1/circuits.json"
	if res, isErr := call(t, "search_circuits", map[string]string{}); !isErr || !strings.Contains(res["error"].(string), "needs the network") {
		t.Errorf("no network = %v", res)
	}
}

func TestLintTool(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "variables.tf"), []byte("variable \"a\" {\n  default = \"0.0.0.0\"\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, isErr := call(t, "lint", map[string]string{"dir": dir})
	if isErr || res["failed"] != true || !strings.Contains(mustJSON(res), `"rule":"C3X003"`) {
		t.Errorf("lint = %v", res)
	}
	if res, isErr := call(t, "lint", map[string]string{"dir": filepath.Join(dir, "nope")}); !isErr || !strings.Contains(res["error"].(string), "can't read") {
		t.Errorf("a missing directory = %v", res)
	}
}

// The tools that read a directory stay inside the one conn3x mcp was
// started in, and the two that run conn3x there refuse provider plugins.
func TestToolsStayInsideTheStartDirectory(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, outside := filepath.Join(base, "root"), filepath.Join(base, "outside")
	for _, d := range []string{filepath.Join(root, "circuit"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "plan.bin"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// Self is a name that can't run: a tool that gets as far as running
	// conn3x fails with another error than the ones looked for here.
	o := Options{Self: filepath.Join(base, "no-such-conn3x"), Root: root}
	for _, tool := range []string{"validate", "lint"} {
		for _, dir := range []string{outside, "../outside", "link", "circuit/../../outside", "/"} {
			if res, isErr := callWith(t, o, tool, map[string]string{"dir": dir}); !isErr || !strings.Contains(res["error"].(string), "outside") {
				t.Errorf("%s of %s = %v, want it refused as outside the start directory", tool, dir, res)
			}
		}
	}
	for _, args := range []map[string]string{
		{"plan_file": filepath.Join(outside, "plan.bin")},
		{"plan_file": "link/plan.bin"},
		{"plan_file": "circuit/plan.bin", "dir": outside},
	} {
		if err := os.WriteFile(filepath.Join(root, "circuit", "plan.bin"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if res, isErr := callWith(t, o, "summarise_plan", args); !isErr || !strings.Contains(res["error"].(string), "outside") {
			t.Errorf("summarise_plan %v = %v, want it refused as outside the start directory", args, res)
		}
	}
	if res, isErr := callWith(t, o, "lint", map[string]string{"dir": "circuit"}); isErr {
		t.Errorf("lint inside the start directory = %v", res)
	}

	locked, cached := filepath.Join(root, "locked"), filepath.Join(root, "cached")
	if err := os.MkdirAll(filepath.Join(cached, ".terraform", "providers", "registry.opentofu.org"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, ".terraform.lock.hcl"), []byte("provider \"registry.opentofu.org/x/marker\" {\n  version = \"1.0.0\"\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{locked, cached} {
		for tool, args := range map[string]map[string]string{"validate": {"dir": dir}, "summarise_plan": {"plan_file": "circuit/plan.bin", "dir": dir}} {
			res, isErr := callWith(t, o, tool, args)
			if !isErr || !strings.Contains(res["error"].(string), "-allow-plugins") {
				t.Errorf("%s in %s = %v, want it refused for its provider plugins", tool, dir, res)
			}
		}
		if err := noPlugins(Options{Root: root, AllowPlugins: true}, dir); err != nil {
			t.Errorf("with -allow-plugins, %s is refused: %v", dir, err)
		}
	}
	if err := noPlugins(o, filepath.Join(root, "circuit")); err != nil {
		t.Errorf("a directory with no plugins is refused: %v", err)
	}
}

func TestSearchCircuitsRefusesAnOversizedCatalogue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"format_version":"1","circuits":[{"name":"`))
		_, _ = w.Write(bytes.Repeat([]byte("a"), maxCatalogue))
		_, _ = w.Write([]byte(`"}]}`))
	}))
	defer srv.Close()
	saved := CatalogueURL
	defer func() { CatalogueURL = saved }()
	CatalogueURL = srv.URL
	if res, isErr := call(t, "search_circuits", map[string]string{}); !isErr || !strings.Contains(res["error"].(string), "MiB") {
		t.Errorf("an oversized catalogue = %.200v", res)
	}
}

func TestPlanAction(t *testing.T) {
	for in, want := range map[string]string{"create": "create", "update": "update", "delete": "remove", "delete,create": "replace", "create,delete": "replace", "no-op": "", "read": ""} {
		if got := planAction(strings.Split(in, ",")); got != want {
			t.Errorf("planAction(%s) = %q, want %q", in, got, want)
		}
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
