// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
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
	s := &Server{Name: "conn3x", Version: "test", Tools: Tools("conn3x")}
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

func call(t *testing.T, tool string, args any) (map[string]any, bool) {
	t.Helper()
	for _, tl := range Tools("conn3x") {
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
	if res, isErr := call(t, "lint", map[string]string{"dir": filepath.Join(dir, "nope")}); !isErr || !strings.Contains(res["error"].(string), "isn't a directory") {
		t.Errorf("a missing directory = %v", res)
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
