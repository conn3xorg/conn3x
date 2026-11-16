// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/command/arguments"
	runreport "github.com/opentofu/opentofu/internal/conn3x/report"
)

func TestReportIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix file modes")
	}
	path := filepath.Join(t.TempDir(), "run.json")
	if err := writeReport(path, runreport.New("apply", time.Now())); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Fatalf("report mode = %o, want 600", mode)
	}
}

// A report file that's already there doesn't keep its wider mode, and a
// link there is replaced, not followed to what it points at.
func TestReportReplacesWhatIsAtItsPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix file modes")
	}
	dir := t.TempDir()
	path, victim := filepath.Join(dir, "run.json"), filepath.Join(dir, "victim")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeReport(path, runreport.New("apply", time.Now())); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("a report written over a 0644 file has mode %o, want 600", st.Mode().Perm())
	}

	if err := os.WriteFile(victim, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := writeReport(link, runreport.New("apply", time.Now())); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(victim); string(got) != "keep me" {
		t.Errorf("the report was written through the link, to its target: %q", got)
	}
	if st, _ := os.Lstat(link); !st.Mode().IsRegular() {
		t.Errorf("the link at the report's path wasn't replaced: %v", st.Mode())
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*")); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

// A line of the stream too long to read doesn't lose the report or fail
// the apply: the report is written from the rest.
func TestApplyReportSurvivesALongLine(t *testing.T) {
	saved := runreport.MaxLine
	runreport.MaxLine = 1 << 10
	defer func() { runreport.MaxLine = saved }()
	dir := t.TempDir()
	stream := filepath.Join(dir, "stream.json")
	lines := `{"type":"planned_change","change":{"resource":{"addr":"module.web.conn3x_file.motd[\"a\"]","resource_type":"conn3x_file"},"action":"create"}}` + "\n" +
		`{"type":"outputs","outputs":{"big":"` + strings.Repeat("x", 4<<10) + `"}}` + "\n" +
		`{"type":"apply_complete","hook":{"resource":{"addr":"module.web.conn3x_file.motd[\"a\"]","resource_type":"conn3x_file"},"action":"create","elapsed_seconds":1}}` + "\n"
	if err := os.WriteFile(stream, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "run.json")
	err := writeApplyReport(path, stream, time.Now(), true)
	var long runreport.LongLines
	if !errors.As(err, &long) || long != 1 {
		t.Fatalf("err = %v, want one long line reported", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || !strings.Contains(string(got), `"status": "ok"`) || !strings.Contains(string(got), `"success": true`) {
		t.Fatalf("the report wasn't written from the rest of the stream (%v):\n%s", readErr, got)
	}
}

func TestWithoutReport(t *testing.T) {
	got := withoutReport([]string{"drift", "-no-color", "-report=a.json", "-report", "b.json", "--report=c.json", "-var=x=1"})
	if len(got) != 3 || got[0] != "drift" || got[1] != "-no-color" || got[2] != "-var=x=1" {
		t.Fatalf("withoutReport = %q", got)
	}
}

// fakeApply is an apply command whose run writes one created step to
// -json-into, as conn3x apply -json-into does, and exits code.
func fakeApply(code int, args ...string) command.Command {
	cmd := command.Command{Name: "apply", CommandLine: arguments.CommandLine{View: &arguments.View{}}}
	view := cmd.CommandLine.View
	cmd.Run = func(command.Meta) int {
		if view.JSONInto != nil {
			_, _ = view.JSONInto.WriteString(`{"type":"apply_complete","hook":{"resource":{"addr":"module.web.conn3x_file.motd[\"a\"]","resource_type":"conn3x_file"},"action":"create","elapsed_seconds":1}}` + "\n")
		}
		return code
	}
	withReport(&cmd)
	cmd.CommandLine.ParseLegacy(args)
	return cmd
}

func TestReportFlag(t *testing.T) {
	var errOut bytes.Buffer
	old := stderr
	stderr = &errOut
	t.Cleanup(func() { stderr = old })
	dir := t.TempDir()
	path := filepath.Join(dir, "run.json")
	unwritable := filepath.Join(dir, "missing", "run.json")

	if cmd := fakeApply(0); cmd.Run(command.Meta{}) != 0 {
		t.Fatal("an apply without -report failed")
	}
	cmd := fakeApply(0, "-report="+path)
	if code := cmd.Run(command.Meta{}); code != 0 {
		t.Fatalf("exit %d, %q", code, errOut.String())
	}
	if got, err := os.ReadFile(path); err != nil || !strings.Contains(string(got), `"success": true`) {
		t.Fatalf("report (%v):\n%s", err, got)
	}

	for name, tc := range map[string]struct {
		cmd  command.Command
		json bool
		code int
		want string
	}{
		"with -json":                {fakeApply(0, "-report="+path), true, 1, "-report doesn't go with -json"},
		"a good apply, no report":   {fakeApply(0, "-report="+unwritable), false, 1, "the apply succeeded, but its report wasn't written"},
		"a failed apply, no report": {fakeApply(2, "-report="+unwritable), false, 2, "Error: writing the report"},
	} {
		errOut.Reset()
		if tc.json {
			tc.cmd.CommandLine.View.ViewType = arguments.ViewJSON
		}
		if code := tc.cmd.Run(command.Meta{}); code != tc.code || !strings.Contains(errOut.String(), tc.want) {
			t.Errorf("%s: exit %d, %q", name, code, errOut.String())
		}
	}

	// A line too long to read leaves the report incomplete, which warns
	// and keeps the apply's exit code.
	saved := runreport.MaxLine
	runreport.MaxLine = 16
	defer func() { runreport.MaxLine = saved }()
	errOut.Reset()
	if code := fakeApply(0, "-report="+path).Run(command.Meta{}); code != 0 || !strings.Contains(errOut.String(), "Warning: the report at "+path+" is incomplete") {
		t.Errorf("long line: exit %d, %q", code, errOut.String())
	}
}
