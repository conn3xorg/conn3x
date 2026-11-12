// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"strings"
	"testing"
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
