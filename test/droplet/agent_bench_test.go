// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build droplet

package droplet

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// benchResult is one timed conn3x command, written as a JSON line.
type benchResult struct {
	Run     string  `json:"run"`
	Mode    string  `json:"mode"`  // agent off or on
	Phase   string  `json:"phase"` // cold_apply, refresh_plan or second_plan
	Seconds float64 `json:"seconds"`
}

// TestAgentBench times the same workload on two fresh Rocky droplets, one
// through the shell and one through the agent, both with password sudo.
// It writes JSON lines to CONN3X_BENCH_OUT when set, and a table to the
// GitHub job summary.
//
//	DIGITALOCEAN_TOKEN=... go test -tags droplet -run TestAgentBench -v ./test/droplet/
func TestAgentBench(t *testing.T) {
	r := newRun(t)
	infra := filepath.Join(r.dir, "infra")
	r.render(t, "bench/infra.tf.tmpl", vars{
		RunID:          r.id,
		PublicKey:      r.publicKey,
		PrivateKeyFile: r.keyFile,
		SudoPassword:   r.sudoPassword,
	}, filepath.Join(infra, "main.tf"))
	r.cleanup(t, infra)
	r.must(t, infra, nil, "init", "-no-color")
	r.must(t, infra, nil, "apply", "-auto-approve", "-no-color")
	hostKey := strings.TrimSpace(r.must(t, infra, nil, "output", "-raw", "host_key"))

	pages := make([]string, 45)
	for i := range pages {
		pages[i] = fmt.Sprintf("%02d", i+1)
	}

	var results []benchResult
	for _, mode := range []string{"off", "on"} {
		dir := filepath.Join(r.dir, mode)
		r.render(t, "bench/workload.tf.tmpl", map[string]any{
			"IP":               strings.TrimSpace(r.must(t, infra, nil, "output", "-raw", "ip_"+mode)),
			"HostKey":          hostKey,
			"PrivateKeyFile":   r.keyFile,
			"SudoPasswordFile": r.pwFile,
			"Pages":            pages,
		}, filepath.Join(dir, "main.tf"))
		// require: an apply that can't use the agent fails instead of
		// quietly timing the shell.
		env := []string{"CONN3X_AGENT=off"}
		if mode == "on" {
			env = []string{"CONN3X_AGENT=require"}
		}
		r.must(t, dir, env, "init", "-no-color")
		for _, step := range []struct {
			phase string
			args  []string
			want  string
		}{
			{"cold_apply", []string{"apply", "-auto-approve", "-no-color"}, "66 added"},
			{"refresh_plan", []string{"plan", "-no-color"}, "No changes."},
			{"second_plan", []string{"plan", "-no-color"}, "No changes."},
		} {
			start := time.Now()
			out := r.must(t, dir, env, step.args...)
			res := benchResult{Run: r.id, Mode: mode, Phase: step.phase, Seconds: time.Since(start).Seconds()}
			if !strings.Contains(out, step.want) {
				t.Fatalf("agent %s, %s: want %q in:\n%s", mode, step.phase, step.want, out)
			}
			results = append(results, res)
			line, _ := json.Marshal(res)
			t.Logf("%s", line)
			if path := os.Getenv("CONN3X_BENCH_OUT"); path != "" {
				appendFile(t, path, string(line)+"\n")
			}
		}
	}

	// The agent's ratio for each phase: shell seconds over agent seconds.
	sum := "### Agent benchmark\n\n| | agent off | agent on | speedup |\n|---|---:|---:|---:|\n"
	for i := 0; i < 3; i++ {
		off, on := results[i], results[i+3]
		sum += fmt.Sprintf("| %s | %.1f s | %.1f s | %.2fx |\n", off.Phase, off.Seconds, on.Seconds, off.Seconds/on.Seconds)
	}
	sum += "\nRocky 10, s-1vcpu-1gb, deploy with password sudo; 50 files, 10 packages, 5 services. Gate: refresh_plan at least 2x.\n"
	t.Log("\n" + sum)
	if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
		appendFile(t, path, sum)
	}
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}
