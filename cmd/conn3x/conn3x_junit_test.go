// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/command/arguments"
)

// A test's JSON stream as conn3x test -json writes it: each run's result,
// then its errors.
const junitStream = `{"@level":"info","@testfile":"tests/a.tftest.hcl","@timestamp":"2026-11-11T20:48:48.000000Z","test_file":{"path":"tests/a.tftest.hcl","progress":"starting"},"type":"test_file"}
{"@level":"info","@testfile":"tests/a.tftest.hcl","@testrun":"ok","@timestamp":"2026-11-11T20:48:49.500000Z","test_run":{"path":"tests/a.tftest.hcl","run":"ok","status":"pass"},"type":"test_run"}
{"@level":"info","@testfile":"tests/a.tftest.hcl","@testrun":"bad","@timestamp":"2026-11-11T20:48:50.000000Z","test_run":{"path":"tests/a.tftest.hcl","run":"bad","status":"fail"},"type":"test_run"}
{"@level":"error","@testfile":"tests/a.tftest.hcl","@testrun":"bad","@timestamp":"2026-11-11T20:48:50.000100Z","diagnostic":{"severity":"error","summary":"Test assertion failed","detail":"x should be 2"},"type":"diagnostic"}
not json
{"@level":"info","@testfile":"tests/b.tftest.hcl","@testrun":"later","@timestamp":"2026-11-11T20:48:51.000000Z","test_run":{"path":"tests/b.tftest.hcl","run":"later","status":"skip"},"type":"test_run"}
{"@level":"info","@testfile":"tests/b.tftest.hcl","@testrun":"broken","@timestamp":"2026-11-11T20:48:52.000000Z","test_run":{"path":"tests/b.tftest.hcl","run":"broken","status":"error"},"type":"test_run"}
`

func TestJUnitFromStream(t *testing.T) {
	s, err := junitFrom(strings.NewReader(junitStream))
	if err != nil {
		t.Fatal(err)
	}
	if s.Tests != 4 || s.Failures != 1 || s.Errors != 1 || s.Skipped != 1 || len(s.Suites) != 2 {
		t.Fatalf("totals %+v", s)
	}
	a := s.Suites[0]
	if a.Name != "tests/a.tftest.hcl" || a.Time != "2.000" || a.Cases[0].Time != "1.500" || a.Cases[0].Failure != nil {
		t.Errorf("suite a: %+v", a)
	}
	if f := a.Cases[1].Failure; f == nil || f.Message != "Test assertion failed: x should be 2" {
		t.Errorf("bad's failure: %+v", f)
	}
	b := s.Suites[1].Cases
	if b[0].Skipped == nil || b[1].Error == nil || b[1].Error.Message != "run broken errored" {
		t.Errorf("suite b: %+v", b)
	}
}

// fakeTest is a test command whose run writes junitStream to -json-into,
// as conn3x test does, and exits code.
func fakeTest(code int) command.Command {
	cmd := command.Command{Name: "test", CommandLine: arguments.CommandLine{View: &arguments.View{}}}
	view := cmd.CommandLine.View
	cmd.Run = func(command.Meta) int {
		if view.JSONInto != nil {
			_, _ = view.JSONInto.WriteString(junitStream)
		}
		return code
	}
	withJUnit(&cmd)
	return cmd
}

func TestJUnitFlag(t *testing.T) {
	var errOut bytes.Buffer
	old := stderr
	stderr = &errOut
	t.Cleanup(func() { stderr = old })
	dir := t.TempDir()

	// Without the flag, the test runs as it would.
	cmd := fakeTest(0)
	if code := cmd.Run(command.Meta{}); code != 0 {
		t.Fatalf("no flag: exit %d", code)
	}

	// With it, the XML is written and the test's exit code kept.
	path := filepath.Join(dir, "results.xml")
	cmd = fakeTest(1)
	cmd.CommandLine.ParseLegacy([]string{"-junit-xml=" + path})
	if code := cmd.Run(command.Meta{}); code != 1 {
		t.Fatalf("exit %d, %q", code, errOut.String())
	}
	got, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(got), `<testsuites tests="4" failures="1" errors="1" skipped="1">`) {
		t.Fatalf("results.xml (%v):\n%s", err, got)
	}

	// The caller's own -json-into file is the stream the XML is built from.
	into, err := os.Create(filepath.Join(dir, "stream.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer into.Close()
	cmd = fakeTest(0)
	cmd.CommandLine.View.JSONInto = into
	cmd.CommandLine.ParseLegacy([]string{"-junit-xml=" + path})
	if code := cmd.Run(command.Meta{}); code != 0 {
		t.Fatalf("-json-into: exit %d, %q", code, errOut.String())
	}

	// A test that passed but whose XML can't be written exits 1.
	cmd = fakeTest(0)
	cmd.CommandLine.ParseLegacy([]string{"-junit-xml=" + filepath.Join(dir, "missing", "results.xml")})
	if code := cmd.Run(command.Meta{}); code != 1 || !strings.Contains(errOut.String(), "Error: writing ") {
		t.Fatalf("unwritable: exit %d, %q", code, errOut.String())
	}
}
