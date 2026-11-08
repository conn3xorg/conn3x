// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// conn3x mcp, driven the way an assistant would over stdio: validate a
// circuit, and summarise a saved plan for it per host, with no values in
// the summary.
func TestMCPServer(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "report")
	w.writeAs("main.circuit.hcl", reportVars{Ports: map[string]string{"web1": h.port}, Key: h.keyFile, KnownHosts: h.knownHosts})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("plan", "-no-color", "-out=tfplan")

	cmd := exec.Command(conn3xBin, "mcp")
	cmd.Dir = w.dir
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	lines := bufio.NewScanner(stdout)
	lines.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	ask := func(id int, method, params string) map[string]any {
		t.Helper()
		fmt.Fprintf(stdin, `{"jsonrpc":"2.0","id":%d,"method":%q,"params":%s}`+"\n", id, method, params)
		if !lines.Scan() {
			t.Fatalf("no response to %s", method)
		}
		var m map[string]any
		if err := json.Unmarshal(lines.Bytes(), &m); err != nil {
			t.Fatalf("%s: %v in %q", method, err, lines.Text())
		}
		return m
	}
	tool := func(id int, name, args string) map[string]any {
		t.Helper()
		res := ask(id, "tools/call", fmt.Sprintf(`{"name":%q,"arguments":%s}`, name, args))["result"].(map[string]any)
		if res["isError"] == true {
			t.Fatalf("%s failed: %v", name, res["content"])
		}
		return res["structuredContent"].(map[string]any)
	}

	if v := ask(1, "initialize", `{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}`)["result"].(map[string]any)["protocolVersion"]; v != "2025-06-18" {
		t.Fatalf("protocolVersion = %v", v)
	}
	fmt.Fprintln(stdin, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)

	if v := tool(2, "validate", `{"dir":"."}`); v["valid"] != true {
		t.Errorf("validate = %v", v)
	}
	sum := tool(3, "summarise_plan", `{"plan_file":"tfplan"}`)
	t.Logf("summary: %v", sum)
	steps := sum["hosts"].(map[string]any)["web1"].([]any)
	if len(steps) != 2 || steps[0].(map[string]any)["step"] != "r.first" || steps[1].(map[string]any)["action"] != "create" {
		t.Errorf("web1's steps = %v", steps)
	}
	if b, _ := json.Marshal(sum); strings.Contains(string(b), "managed") {
		t.Error("the summary holds an attribute value")
	}
}
