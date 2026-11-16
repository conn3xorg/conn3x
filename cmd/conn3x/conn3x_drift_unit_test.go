// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	runreport "github.com/opentofu/opentofu/internal/conn3x/report"
)

// runPlan reads the plan's stream and keeps its exit code, and says when
// the plan couldn't start or its stream couldn't be read in full.
func TestRunPlanReadsTheStream(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the plan here is a sh script")
	}
	drifted := `{"type":"resource_drift","change":{"resource":{"addr":"conn3x_file.a","resource_type":"conn3x_file"},"action":"update"}}`
	var errOut strings.Builder
	r, code, err := runPlan(exec.Command("sh", "-c", "echo '"+drifted+"'; echo planning >&2; exit 2"), &errOut)
	if err != nil || code != 2 || len(r.hosts) != 1 || errOut.String() != "planning\n" {
		t.Fatalf("exit %d, %+v, %v, stderr %q", code, r, err, errOut.String())
	}

	if _, code, err := runPlan(exec.Command(filepath.Join(t.TempDir(), "no-conn3x")), &errOut); code != 1 || err == nil || !strings.Contains(err.Error(), "running the plan") {
		t.Errorf("a plan that can't start: exit %d, %v", code, err)
	}

	saved := runreport.MaxLine
	runreport.MaxLine = 16
	defer func() { runreport.MaxLine = saved }()
	if _, code, err := runPlan(exec.Command("sh", "-c", "echo '"+drifted+"'"), &errOut); code != 1 || err == nil || !strings.Contains(err.Error(), "drift can't say what changed") {
		t.Errorf("a long line: exit %d, %v", code, err)
	}
}
