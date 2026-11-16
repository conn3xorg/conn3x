// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	runreport "github.com/opentofu/opentofu/internal/conn3x/report"
)

// A report to something that isn't a file, such as /dev/null, is written
// to it as it is; one to a directory that isn't there is an error.
func TestWriteReportTargets(t *testing.T) {
	rep := runreport.New("apply", time.Now())
	if err := writeReport("/dev/null", rep); err != nil {
		t.Errorf("/dev/null: %v", err)
	}
	if err := writeReport(filepath.Join(t.TempDir(), "missing", "run.json"), rep); err == nil {
		t.Error("wrote a report into a directory that isn't there")
	}
}

// A saved plan's apply keeps only the options apply takes with one.
func TestBatchApplyArgsKeepsSavedPlanOptions(t *testing.T) {
	r := &batchRun{args: []string{"apply", "-lock=false", "-lock-timeout=5s", "-compact-warnings", "-concise", "-show-sensitive", "-var=a=1", "-refresh=false"}}
	if got := strings.Join(r.applyArgs("p"), " "); got != "apply -lock=false -lock-timeout=5s -compact-warnings -concise -show-sensitive p" {
		t.Errorf("applyArgs = %s", got)
	}
}
