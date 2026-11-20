// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// eachRepo is a git repository with network, app reading network's state,
// and old, which the test then deletes.
func eachRepo(t *testing.T) string {
	t.Helper()
	// The user's git config, such as signed tags, stays out of the test.
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	root := t.TempDir()
	write := func(p, content string) {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("network/main.tf", "terraform {\n  backend \"local\" {\n    path = \"n.tfstate\"\n  }\n}\n")
	write("app/main.tf", "data \"terraform_remote_state\" \"n\" {\n  backend = \"local\"\n  config  = { path = \"../network/n.tfstate\" }\n}\n")
	write("old/main.tf", "output \"x\" { value = 1 }\n")
	write("docs/readme.md", "docs\n")
	git := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s", args, out)
		}
	}
	git("init", "-q", "-b", "main")
	git("add", ".")
	git("commit", "-q", "-m", "base")
	git("tag", "base")
	return root
}

// fakeRun records the order of calls and answers plan with codes by dir.
type fakeRun struct {
	mu    sync.Mutex
	calls []string
	codes map[string]int
}

func (f *fakeRun) run(dir string, args ...string) ([]byte, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, dir+" "+args[0])
	if args[0] == "plan" {
		return []byte("planned " + dir + "\n"), f.codes[dir], nil
	}
	return nil, 0, nil
}

func TestEachPlanOrderAndSummary(t *testing.T) {
	root := eachRepo(t)
	f := &fakeRun{codes: map[string]int{"app": 2}}
	var out, errOut bytes.Buffer
	code := runEachPlan(eachOptions{parallelism: 1, detailedExitcode: true}, root, f.run, &out, &errOut)
	if code != 2 {
		t.Fatalf("exit %d, want 2 for changes:\n%s%s", code, out.String(), errOut.String())
	}
	// Every init first, level by level, then the plans: app after network.
	if got := strings.Join(f.calls, ", "); got != "network init, old init, app init, network plan, old plan, app plan" {
		t.Errorf("calls: %s", got)
	}
	for _, want := range []string{"app: planned app", "\napp: changes\nnetwork: no changes\nold: no changes\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output is missing %q:\n%s", want, out.String())
		}
	}
}

// -changed plans what a change touched and what depends on it, counts an
// untracked new file, and names a configuration the change removed.
func TestEachPlanChanged(t *testing.T) {
	root := eachRepo(t)
	if err := os.WriteFile(filepath.Join(root, "network", "extra.tf"), []byte("output \"y\" { value = 2 }\n"), 0o644); err != nil { // untracked
		t.Fatal(err)
	}
	// What an earlier init left in app isn't a change to app.
	for _, p := range []string{"app/.terraform/terraform.tfstate", "app/.terraform.lock.hcl", "app/terraform.tfstate"} {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.RemoveAll(filepath.Join(root, "old")); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "commit", "-qam", "drop old")
	cmd.Dir = root
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s", b)
	}
	f := &fakeRun{codes: map[string]int{}}
	var out, errOut bytes.Buffer
	if code := runEachPlan(eachOptions{changed: "base", parallelism: 2}, root, f.run, &out, &errOut); code != 0 {
		t.Fatalf("exit %d:\n%s%s", code, out.String(), errOut.String())
	}
	if got := strings.Join(f.calls, ", "); got != "network init, app init, network plan, app plan" {
		t.Errorf("calls: %s", got)
	}
	if !strings.Contains(out.String(), "old: removed by this change, but its resources are still in its state") {
		t.Errorf("old's removal isn't named:\n%s", out.String())
	}

	// A change to docs alone plans nothing.
	f = &fakeRun{codes: map[string]int{}}
	out.Reset()
	os.Remove(filepath.Join(root, "network", "extra.tf"))
	if err := os.WriteFile(filepath.Join(root, "docs", "readme.md"), []byte("more\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "commit", "-qam", "docs")
	cmd.Dir = root
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s", b)
	}
	if code := runEachPlan(eachOptions{changed: "HEAD~1", parallelism: 1}, root, f.run, &out, &errOut); code != 0 || len(f.calls) != 0 || !strings.Contains(out.String(), "No root configuration to plan.") {
		t.Errorf("docs only: exit %d, calls %v:\n%s", code, f.calls, out.String())
	}
}

// A failed plan skips what depends on it, and the run exits 1.
func TestEachPlanFailureSkipsDependents(t *testing.T) {
	root := eachRepo(t)
	f := &fakeRun{codes: map[string]int{"network": 1}}
	var out, errOut bytes.Buffer
	if code := runEachPlan(eachOptions{parallelism: 1, keepGoing: true}, root, f.run, &out, &errOut); code != 1 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"app: skipped: network didn't plan", "network: failed", "old: no changes"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output is missing %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(strings.Join(f.calls, ","), "app plan") {
		t.Error("app planned after network failed")
	}
}

// A file moved from one configuration to another changes both, and a
// configuration moved away whole is gone, whether the move is committed
// or not.
func TestEachChangesSeeMoves(t *testing.T) {
	root := eachRepo(t)
	git := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s", args, out)
		}
	}
	git("mv", "old/main.tf", "network/old.tf")
	files, gone, err := gitChanges(root, "base")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(gone, ",") != "old" || !slices.Contains(files, "old/main.tf") || !slices.Contains(files, "network/old.tf") {
		t.Errorf("uncommitted move: files %v, gone %v", files, gone)
	}
	git("commit", "-qm", "move")
	if files, gone, err = gitChanges(root, "base"); err != nil || strings.Join(gone, ",") != "old" || !slices.Contains(files, "old/main.tf") {
		t.Errorf("committed move: files %v, gone %v, %v", files, gone, err)
	}
}

// jsonRun answers plan as plan -json would, with a change summary for a
// configuration that has changes, and records whether -json was passed.
type jsonRun struct {
	fakeRun
	sawJSON bool
}

func (f *jsonRun) run(dir string, args ...string) ([]byte, int, error) {
	if args[0] == "plan" && slices.Contains(args, "-json") {
		f.mu.Lock()
		f.sawJSON = true
		f.mu.Unlock()
		if f.codes[dir] == 2 {
			f.fakeRun.run(dir, args...)
			return []byte(`{"@level":"info","@message":"Plan: 1 to add, 2 to change, 0 to destroy.","type":"change_summary","changes":{"add":1,"change":2,"import":0,"remove":0,"forget":0,"operation":"plan"}}` + "\n"), 2, nil
		}
	}
	return f.fakeRun.run(dir, args...)
}

// With -json, stdout is one object per configuration, and the plans' own
// output goes to stderr.
func TestEachPlanJSON(t *testing.T) {
	root := eachRepo(t)
	f := &jsonRun{fakeRun: fakeRun{codes: map[string]int{"app": 2}}}
	var out, errOut bytes.Buffer
	if code := runEachPlan(eachOptions{parallelism: 1, json: true}, root, f.run, &out, &errOut); code != 0 || !f.sawJSON {
		t.Fatalf("exit %d, -json passed %t:\n%s%s", code, f.sawJSON, out.String(), errOut.String())
	}
	want := `{"changes":{"add":1,"change":2,"import":0,"remove":0,"forget":0},"dir":"app","result":"changes"}` + "\n" +
		`{"dir":"network","result":"no changes"}` + "\n" +
		`{"dir":"old","result":"no changes"}` + "\n"
	if out.String() != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", out.String(), want)
	}
	if !strings.Contains(errOut.String(), "network: planned network") {
		t.Errorf("plan output didn't go to stderr:\n%s", errOut.String())
	}

	f = &jsonRun{fakeRun: fakeRun{codes: map[string]int{"network": 1}}}
	out.Reset()
	if code := runEachPlan(eachOptions{parallelism: 1, keepGoing: true, json: true}, root, f.run, &out, &errOut); code != 1 {
		t.Fatalf("failure: exit %d", code)
	}
	for _, line := range []string{`{"because":"network","dir":"app","result":"skipped"}`, `{"dir":"network","result":"failed"}`} {
		if !strings.Contains(out.String(), line+"\n") {
			t.Errorf("stdout lacks %s:\n%s", line, out.String())
		}
	}
	var o map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if err := json.Unmarshal([]byte(l), &o); err != nil {
			t.Errorf("%q isn't JSON: %v", l, err)
		}
	}
}
