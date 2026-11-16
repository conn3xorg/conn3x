// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package mcp

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestMain lets the test binary stand in for conn3x, which validate and
// summarise_plan run as Self. With CONN3X_MCP_FAKE set to a directory, it
// prints the file there named for its subcommand, such as validate.json,
// and exits with CONN3X_MCP_FAKE_EXIT; without the file it fails, saying
// what it was run with.
func TestMain(m *testing.M) {
	if dir := os.Getenv("CONN3X_MCP_FAKE"); dir != "" {
		out, err := os.ReadFile(filepath.Join(dir, os.Args[1]+".json"))
		if err != nil {
			os.Stderr.WriteString("Error: no " + strings.Join(os.Args[1:], " ") + "\n")
			os.Exit(1)
		}
		os.Stdout.Write(out)
		code, _ := strconv.Atoi(os.Getenv("CONN3X_MCP_FAKE_EXIT"))
		os.Exit(code)
	}
	os.Exit(m.Run())
}

// fakeConn3x makes a start directory holding circuit, and options that run
// the test binary as conn3x, answering each subcommand from outputs.
func fakeConn3x(t *testing.T, exit int, outputs map[string]string) (Options, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(root, ".fake")
	for _, d := range []string{fake, filepath.Join(root, "circuit")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for cmd, out := range outputs {
		if err := os.WriteFile(filepath.Join(fake, cmd+".json"), []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CONN3X_MCP_FAKE", fake)
	t.Setenv("CONN3X_MCP_FAKE_EXIT", strconv.Itoa(exit))
	return Options{Self: os.Args[0], Root: root}, root
}

// validate exits 1 for a circuit with errors and still prints them.
func TestValidateTool(t *testing.T) {
	o, _ := fakeConn3x(t, 1, map[string]string{"validate": `{"valid":false,"diagnostics":[
		{"severity":"error","summary":"Unsupported argument","detail":"An argument named \"x\" is not expected here.","range":{"filename":"main.tf","start":{"line":3}}},
		{"severity":"warning","summary":"Deprecated"}]}`})
	res, isErr := callWith(t, o, "validate", map[string]string{"dir": "circuit"})
	if isErr || res["valid"] != false {
		t.Fatalf("validate = %v", res)
	}
	want := `{"diagnostics":[{"detail":"An argument named \"x\" is not expected here.","file":"main.tf","line":3,"severity":"error","summary":"Unsupported argument"},{"severity":"warning","summary":"Deprecated"}],"valid":false}`
	if got := mustJSON(res); got != want {
		t.Errorf("validate = %s\nwant %s", got, want)
	}
	o, _ = fakeConn3x(t, 0, map[string]string{"validate": `{"valid":true,"diagnostics":[]}`})
	if res, isErr := callWith(t, o, "validate", map[string]string{"dir": "circuit"}); isErr || mustJSON(res) != `{"diagnostics":[],"valid":true}` {
		t.Errorf("a valid circuit = %v", res)
	}
}

func TestValidateToolErrors(t *testing.T) {
	for name, c := range map[string]struct {
		exit    int
		outputs map[string]string
		want    string
	}{
		"not JSON": {0, map[string]string{"validate": "Success!"}, "reading conn3x validate's output"},
		// A failure with nothing on stdout is reported with its stderr.
		"no output": {1, nil, "conn3x validate failed: Error: no validate -json -no-color"},
	} {
		o, _ := fakeConn3x(t, c.exit, c.outputs)
		if res, isErr := callWith(t, o, "validate", map[string]string{"dir": "circuit"}); !isErr || !strings.HasPrefix(res["error"].(string), c.want) {
			t.Errorf("%s: %v, want %q", name, res, c.want)
		}
	}
	o, _ := fakeConn3x(t, 0, nil)
	o.Self = filepath.Join(o.Root, "no-such-conn3x")
	if res, isErr := callWith(t, o, "validate", map[string]string{"dir": "circuit"}); !isErr || !strings.Contains(res["error"].(string), "no-such-conn3x") {
		t.Errorf("a conn3x that can't start = %v", res)
	}
}

func TestSummarisePlanTool(t *testing.T) {
	o, root := fakeConn3x(t, 0, map[string]string{"show": `{"resource_changes":[
		{"address":"conn3x_package.web__nginx[\"web1\"]","change":{"actions":["create"]}},
		{"address":"module.edge.conn3x_file.web__motd[\"web1/banner\"]","change":{"actions":["delete","create"]}},
		{"address":"conn3x_service.web__nginx[\"web1\"]","change":{"actions":["no-op"]}},
		{"address":"aws_instance.web","change":{"actions":["update"]}}]}`})
	if err := os.WriteFile(filepath.Join(root, "circuit", "plan.bin"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	res, isErr := callWith(t, o, "summarise_plan", map[string]string{"plan_file": "circuit/plan.bin"})
	if isErr {
		t.Fatal(res)
	}
	// Steps go under their host, everything else is cloud, and a no-op is
	// left out of both and of the counts.
	want := `{"cloud":[{"action":"update","address":"aws_instance.web"}],"counts":{"create":1,"replace":1,"update":1},` +
		`"hosts":{"web1":[{"action":"create","address":"conn3x_package.web__nginx[\"web1\"]","step":"web.nginx"},` +
		`{"action":"replace","address":"module.edge.conn3x_file.web__motd[\"web1/banner\"]","item":"banner","step":"module.edge.web.motd"}]}}`
	if got := mustJSON(res); got != want {
		t.Errorf("summary = %s\nwant %s", got, want)
	}

	for name, c := range map[string]struct {
		args map[string]string
		want string
	}{
		"no plan file":    {map[string]string{}, "plan_file is required"},
		"dir is a file":   {map[string]string{"plan_file": "circuit/plan.bin", "dir": "circuit/plan.bin"}, "isn't a directory"},
		"unknown field":   {map[string]string{"plan_file": "circuit/plan.bin", "out": "x"}, "out"},
		"unreadable plan": {map[string]string{"plan_file": "circuit/plan.bin"}, "reading the plan"},
	} {
		if name == "unreadable plan" {
			o, root = fakeConn3x(t, 0, map[string]string{"show": "not a plan"})
			if err := os.WriteFile(filepath.Join(root, "circuit", "plan.bin"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if res, isErr := callWith(t, o, "summarise_plan", c.args); !isErr || !strings.Contains(res["error"].(string), c.want) {
			t.Errorf("%s: %v, want %q", name, res, c.want)
		}
	}
}
