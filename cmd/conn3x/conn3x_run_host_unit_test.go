// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
)

// brMarker answers a shell where "make-marker" creates /done, which a
// creates guard looks for, and "fail" exits 2.
type brMarker struct {
	mu   sync.Mutex
	done bool
}

func (m *brMarker) answer(cmd string, _ []byte) (string, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cmd = strings.ReplaceAll(strings.NewReplacer(`'"'"'`, "'", `'"\\"'`, `\`).Replace(cmd), `'\''`, "'")
	switch {
	case strings.Contains(cmd, "[ -e '/done' ]"):
		if m.done {
			return "", 0
		}
		return "", 1
	case strings.HasSuffix(cmd, "; make-marker'"):
		m.done = true
		return "made\nit\n", 0
	case strings.HasSuffix(cmd, "; fail'"):
		return "it broke", 2
	}
	return "", 0
}

// brInventory writes an inventory with a host for each answer, web1 and
// up, each on an SSH server of its own.
func brInventory(t *testing.T, answers ...func(string, []byte) (string, int)) string {
	t.Helper()
	t.Setenv("CONN3X_AGENT", "off")
	var lines []string
	for i, a := range answers {
		s := sshtest.New(t)
		s.SetExec(a)
		lines = append(lines, fmt.Sprintf("web%d ansible_host=%s ansible_port=%d ansible_user=root ansible_ssh_private_key_file=%s conn3x_ssh_known_hosts_file=%s", i+1, s.Host, s.Port, s.KeyFile(t), s.KnownHosts(t)))
	}
	p := filepath.Join(t.TempDir(), "inventory.ini")
	if err := os.WriteFile(p, []byte("[web]\n"+strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func brRun(o runOptions) (int, string, string) {
	var out, errOut bytes.Buffer
	if o.pattern == "" {
		o.pattern = "all"
	}
	code := runRun(context.Background(), o, &out, &errOut)
	return code, out.String(), errOut.String()
}

// Each host prints its outcome and what the command printed; one that
// fails makes the run exit 2.
func TestRunOnHosts(t *testing.T) {
	inv := brInventory(t, (&brMarker{}).answer, (&brMarker{}).answer)
	code, out, errOut := brRun(runOptions{inventory: inv, args: "make-marker", forks: 2})
	if want := "web1 | changed\n  made\n  it\nweb2 | changed\n  made\n  it\n"; code != 0 || out != want {
		t.Fatalf("exit %d, %q, %q", code, out, errOut)
	}
	code, out, _ = brRun(runOptions{inventory: inv, args: "fail", pattern: "web2"})
	if code != 2 || !strings.HasPrefix(out, "web2 | failed: command failed with exit status 2") || !strings.Contains(out, "it broke") {
		t.Errorf("a failing command: exit %d, %q", code, out)
	}
}

// With a guard, -check says what would change without changing it, and a
// host already in line is ok.
func TestRunCheckAndGuards(t *testing.T) {
	m := &brMarker{}
	inv := brInventory(t, m.answer)
	o := runOptions{inventory: inv, module: "command", args: "command=make-marker creates=/done", check: true}
	if code, out, errOut := brRun(o); code != 0 || out != "web1 | would change\n" {
		t.Fatalf("check: exit %d, %q, %q", code, out, errOut)
	}
	o.check = false
	if code, out, _ := brRun(o); code != 0 || !strings.HasPrefix(out, "web1 | changed") {
		t.Fatalf("apply: exit %d, %q", code, out)
	}
	if code, out, _ := brRun(o); code != 0 || out != "web1 | ok\n" {
		t.Errorf("again: exit %d, %q", code, out)
	}
}

// Once more hosts fail than -max-failures allows, the batches after are
// skipped, and say why.
func TestRunSkipsPastMaxFailures(t *testing.T) {
	broken := func(string, []byte) (string, int) { return "the disk is full", 1 }
	inv := brInventory(t, broken, (&brMarker{}).answer)
	code, out, _ := brRun(runOptions{inventory: inv, args: "make-marker", batchSize: "1"})
	if code != 2 || !strings.Contains(out, "web1 | failed") || !strings.Contains(out, "web2 | skipped: 1 hosts failed, more than -max-failures 0") {
		t.Errorf("exit %d, %q", code, out)
	}
	code, out, _ = brRun(runOptions{inventory: inv, args: "make-marker", batchSize: "50%", maxFailures: 1})
	if code != 2 || !strings.Contains(out, "web2 | changed") {
		t.Errorf("within -max-failures: exit %d, %q", code, out)
	}
	// -json prints a line for each host.
	code, out, _ = brRun(runOptions{inventory: inv, args: "make-marker", json: true})
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
		lines = append(lines, m)
	}
	if code != 2 || len(lines) != 2 || lines[0]["status"] != "failed" || lines[1]["stdout"] != "made\nit\n" {
		t.Errorf("json: exit %d, %v", code, lines)
	}
}

// A task's steps run in order on each host, and stop at the first that
// fails; each step's output prints under the host.
func TestRunTaskOnHosts(t *testing.T) {
	dir := t.TempDir()
	task := filepath.Join(dir, "t.task.hcl")
	body := `task "t" {
  param "cmd" {}
  step "first" {
    command {
      command = "make-marker"
      creates = "/done"
    }
  }
  step "second" {
    command { command = param.cmd }
  }
}
`
	if err := os.WriteFile(task, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	inv := brInventory(t, (&brMarker{}).answer)
	code, out, errOut := brRun(runOptions{inventory: inv, task: task, args: "cmd=fail"})
	if code != 2 || !strings.Contains(out, "web1 | failed\n  first: changed\n    made\n    it\n  second: failed: command failed with exit status 2") {
		t.Fatalf("exit %d, %q, %q", code, out, errOut)
	}
	code, out, _ = brRun(runOptions{inventory: inv, task: task, args: "cmd=make-marker", check: true})
	if code != 0 || out != "web1 | would change\n  first: ok\n  second: would change\n" {
		t.Errorf("check: exit %d, %q", code, out)
	}
	code, out, _ = brRun(runOptions{inventory: inv, task: task, args: "cmd=make-marker", json: true})
	var line struct {
		Host, Status string
		Steps        []taskResult
	}
	if err := json.Unmarshal([]byte(out), &line); err != nil || code != 0 || line.Status != "changed" || len(line.Steps) != 2 {
		t.Errorf("json: exit %d, %q, %v", code, out, err)
	}
}

// A plan's runs go one after the other, each on its hosts; once one fails,
// the rest are skipped.
func TestRunPlanOnHosts(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("ok.task.hcl", "task \"ok\" {\n  step \"s\" {\n    command { command = \"make-marker\" }\n  }\n}\n")
	write("bad.task.hcl", "task \"bad\" {\n  step \"s\" {\n    command { command = \"fail\" }\n  }\n}\n")
	plan := write("p.plan.hcl", "plan \"p\" {\n  run \"one\" {\n    task  = \"ok.task.hcl\"\n    hosts = \"web\"\n  }\n  run \"two\" {\n    task  = \"bad.task.hcl\"\n    hosts = \"web1\"\n  }\n  run \"three\" {\n    task  = \"ok.task.hcl\"\n    hosts = \"all\"\n  }\n}\n")
	inv := brInventory(t, (&brMarker{}).answer, (&brMarker{}).answer)
	code, out, errOut := brRun(runOptions{inventory: inv, plan: plan})
	if code != 2 || !strings.Contains(out, "web2 | changed") || !strings.Contains(out, "== two: task bad, 1 host(s)\nweb1 | failed") || !strings.Contains(out, "== three: skipped, since two failed") {
		t.Errorf("exit %d\nout\n%s\nerr\n%s", code, out, errOut)
	}
	code, out, errOut = brRun(runOptions{inventory: inv, plan: plan, json: true})
	if code != 2 || !strings.Contains(out, `"run":"one"`) || !strings.Contains(out, `"run":"two"`) || !strings.Contains(out, `{"run":"three","status":"skipped"}`) {
		t.Errorf("json: exit %d\nout\n%s\nerr\n%s", code, out, errOut)
	}
}
