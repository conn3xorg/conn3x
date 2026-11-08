// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

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

func TestWithoutReport(t *testing.T) {
	got := withoutReport([]string{"drift", "-no-color", "-report=a.json", "-report", "b.json", "--report=c.json", "-var=x=1"})
	if len(got) != 3 || got[0] != "drift" || got[1] != "-no-color" || got[2] != "-var=x=1" {
		t.Fatalf("withoutReport = %q", got)
	}
}
