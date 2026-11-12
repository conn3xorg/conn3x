// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const batchStep = `step "motd" {
    command {
      command = "true"
    }
  }`

func TestCircuitBatchErrors(t *testing.T) {
	for attrs, want := range map[string]string{
		`batch_size = 2`: "strategy = \"per_host\"",
		`strategy = "per_host"` + "\n" + `batch_size = 0`:                              "isn't a number of hosts",
		`strategy = "per_host"` + "\n" + `batch_size = "0%"`:                           "isn't a percentage",
		`strategy = "per_host"` + "\n" + `batch_size = var.n`:                          "must be a constant",
		`strategy = "per_host"` + "\n" + `max_failures = 1`:                            "needs batch_size",
		`strategy = "per_host"` + "\n" + `batch_size = 2` + "\n" + `max_failures = -1`: "whole number",
	} {
		_, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": onceCircuit(attrs, batchStep)})
		if !strings.Contains(diags.Error(), want) {
			t.Errorf("%s: got %q, want %q", attrs, diags.Error(), want)
		}
	}
}

func TestCircuitBatchRefusesRunOnce(t *testing.T) {
	_, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": onceCircuit(`strategy = "per_host"`+"\n"+`batch_size = 1`, `step "migrate" {
    run_once = true
    command {
      command = "true"
    }
  }`)})
	if !strings.Contains(diags.Error(), "run_once in a batched circuit") {
		t.Fatalf("got %q", diags.Error())
	}
}

func TestConn3xBatches(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"web.circuit.hcl": strings.Replace(onceCircuit(`strategy = "per_host"`+"\n"+`batch_size = "40%"`+"\n"+`max_failures = 1`, batchStep), `"app"`, `"web"`, 1),
		"db.circuit.hcl":  onceCircuit(`strategy = "per_host"`, batchStep),
		"main.tf":         `circuit "ignored" { batch_size = 1 }`,
	}
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, diags := Conn3xBatches(dir)
	if diags.HasErrors() || len(got) != 1 {
		t.Fatalf("got %+v, %v", got, diags)
	}
	if b := got[0]; b != (Conn3xBatch{Circuit: "web", Percent: 40, MaxFailures: 1}) || b.Of(5) != 2 || b.Of(1) != 1 {
		t.Errorf("got %+v, Of(5) = %d", b, b.Of(5))
	}
}
