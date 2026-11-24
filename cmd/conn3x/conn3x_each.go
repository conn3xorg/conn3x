// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/conn3x/each"
	"github.com/opentofu/opentofu/internal/conn3x/termsafe"
)

type eachOptions struct {
	changed          string
	parallelism      int
	keepGoing        bool
	detailedExitcode bool
	json             bool
	args             []string
}

func eachCommand() command.Command {
	var o eachOptions
	plan := command.Command{
		Name:  "plan",
		Short: "Plan every root configuration under this directory, or those a change touched",
		Long: `Plans every root configuration under the current directory, in the order they depend on each other, and prints one line for each at the end.

  conn3x each plan
  conn3x each plan -changed=origin/main

A root configuration is a directory with .tf, .tofu or .circuit.hcl files that no other configuration calls as a local module, or one with a backend block of its own.

One configuration depends on another when its terraform_remote_state reads the state the other's backend writes: the same backend type, with the same bucket and key for s3, bucket and prefix for gcs, storage account, container and key for azurerm, or path for local. Both sides need literal settings for that. Where they aren't, such as a key from a variable or a backend set with -backend-config, it says so, and a conn3x.each.hcl beside the reading configuration names what it depends on:

  depends_on = ["../network"]
  watch      = ["../policies"]

watch lists paths outside the directory that the configuration reads, such as a shared .tfvars or a policy file, so a change to them counts as a change to it.

With -changed=REF, only the configurations a change touched are planned: those with a changed file in their directory, in a local module they call at any depth, or in a watched path, and any configuration that depends on one of those, since its inputs may move. The change is everything since REF: commits (git diff REF...HEAD), uncommitted edits, and new files git doesn't ignore. A configuration the change removed is named in the summary, since its resources are still in its state.

Each configuration is initialised one at a time, then planned, with up to -parallelism plans at once among those that don't depend on each other. After the first failure no new plan starts, unless -keep-going is set; a configuration whose dependency failed is skipped either way.

Arguments after the options go to every plan, as in conn3x each plan -lock-timeout=60s.

With -json, stdout is one JSON object per configuration, for CI or a UI to read: {"dir": "app", "result": "changes", "changes": {"add": 1, "change": 2, "remove": 0}}. result is "no changes", "changes", "failed", "skipped" (with "because", the dependency that didn't plan), "not run" or "removed", and changes comes from each plan's own -json change summary. The plans' own output goes to stderr.

Exits 0 when every plan succeeded and 1 when any failed. With -detailed-exitcode, a run with changes and no failures exits 2.`,
	}
	plan.CommandLine.StringVar(&o.changed, "changed", "", "Plan only the configurations changed since this git ref, and those that depend on them.")
	plan.CommandLine.IntVar(&o.parallelism, "parallelism", 1, "How many configurations to plan at once.")
	plan.CommandLine.BoolVar(&o.keepGoing, "keep-going", false, "Keep starting plans after one fails.")
	plan.CommandLine.BoolVar(&o.detailedExitcode, "detailed-exitcode", false, "Exit 2 when any plan has changes and none failed.")
	plan.CommandLine.BoolVar(&o.json, "json", false, "Print one JSON object per configuration, with its result and change counts, and send the plans' own output to stderr.")
	plan.CommandLine.VariadicArg(&o.args, "PLAN-ARG")
	plan.UsageOverride.Usage = "conn3x [global options] each plan [-changed=REF] [-parallelism=N] [-keep-going] [-detailed-exitcode] [-json] [PLAN-ARG ...]"
	plan.Run = func(command.Meta) int {
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			return 1
		}
		return runEachPlan(o, ".", eachExec(exe), stdout, os.Stderr)
	}
	return command.Command{
		Name:     "each",
		Short:    "Plan every root configuration under a directory, in order",
		Long:     "Runs a command in every root configuration under the current directory, in the order they depend on each other, or only in those a change touched.",
		GroupID:  command.OtherCommandGroup.ID,
		Commands: []command.Command{plan},
	}
}

// eachRunner runs conn3x with args in dir and returns its output and exit
// code; a failure to start it is an error.
type eachRunner func(dir string, args ...string) ([]byte, int, error)

func eachExec(exe string) eachRunner {
	return func(dir string, args ...string) ([]byte, int, error) {
		cmd := exec.Command(exe, append([]string{"-chdir=" + dir}, args...)...)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return out.Bytes(), exit.ExitCode(), nil
		}
		if err != nil {
			return out.Bytes(), -1, err
		}
		return out.Bytes(), 0, nil
	}
}

func runEachPlan(o eachOptions, root string, run eachRunner, stdout, stderr io.Writer) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintln(stderr, termsafe.Escape(fmt.Sprintf("Error: "+format, a...)))
		return 1
	}
	if o.parallelism < 1 {
		return fail("-parallelism must be at least 1")
	}
	tree, err := each.Load(root)
	if err != nil {
		return fail("%s", err)
	}
	dirs := tree.Roots()
	var removed []string
	if o.changed != "" {
		files, gone, err := gitChanges(root, o.changed)
		if err != nil {
			return fail("%s", err)
		}
		dirs = tree.Changed(files)
		for _, d := range gone {
			if _, ok := tree.Configs[d]; !ok {
				removed = append(removed, d)
			}
		}
	}
	for _, p := range tree.Problems {
		fmt.Fprintln(stderr, termsafe.Escape("Warning: "+p))
	}
	levels, err := tree.Levels(dirs)
	if err != nil {
		return fail("%s", err)
	}
	if len(dirs) == 0 {
		if o.json {
			fmt.Fprintln(stderr, "No root configuration to plan.")
		} else {
			fmt.Fprintln(stdout, "No root configuration to plan.")
		}
	}

	result := map[string]string{}
	var mu sync.Mutex
	failed := false
	// With -json, stdout is the results alone, and the plans' own output
	// goes to stderr.
	planOut := stdout
	if o.json {
		planOut = stderr
	}
	print := func(dir string, out []byte) {
		mu.Lock()
		defer mu.Unlock()
		sc := bufio.NewScanner(bytes.NewReader(out))
		sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for sc.Scan() {
			fmt.Fprintln(planOut, termsafe.Escape(dir+": "+sc.Text()))
		}
	}
	counts := map[string]*changeCounts{}
	blocked := func(dir string) string {
		for _, dep := range tree.Edges[dir] {
			if r := result[dep]; r == "failed" || strings.HasPrefix(r, "skipped") {
				return "skipped: " + dep + " didn't plan"
			}
		}
		return ""
	}

	// One init at a time: concurrent inits can race on a shared plugin cache.
	for _, level := range levels {
		for _, dir := range level {
			out, code, err := run(dir, "init", "-input=false", "-no-color")
			if err != nil || code != 0 {
				print(dir, out)
				if err != nil {
					print(dir, []byte(err.Error()))
				}
				result[dir], failed = "failed", true
			}
		}
	}
	for _, level := range levels {
		if failed && !o.keepGoing {
			break
		}
		sem := make(chan struct{}, o.parallelism)
		var wg sync.WaitGroup
		for _, dir := range level {
			if result[dir] != "" {
				continue
			}
			mu.Lock()
			why := blocked(dir)
			if why != "" {
				result[dir] = why
			}
			mu.Unlock()
			if why != "" {
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(dir string) {
				defer wg.Done()
				defer func() { <-sem }()
				args := []string{"plan", "-input=false", "-no-color", "-detailed-exitcode"}
				if o.json {
					args = append(args, "-json")
				}
				out, code, err := run(dir, append(args, o.args...)...)
				print(dir, out)
				r := "failed"
				switch {
				case err != nil:
					print(dir, []byte(err.Error()))
				case code == 0:
					r = "no changes"
				case code == 2:
					r = "changes"
				}
				mu.Lock()
				result[dir] = r
				if o.json && r == "changes" {
					counts[dir] = planChanges(out)
				}
				if r == "failed" {
					failed = true
				}
				mu.Unlock()
			}(dir)
		}
		wg.Wait()
	}

	if !o.json {
		fmt.Fprintln(stdout)
	}
	changes := false
	for _, dir := range dirs {
		r := result[dir]
		if r == "" {
			r = "not run: an earlier plan failed"
		}
		changes = changes || r == "changes"
		if o.json {
			printEachJSON(stdout, dir, r, counts[dir])
			continue
		}
		fmt.Fprintln(stdout, termsafe.Escape(dir+": "+r))
	}
	for _, d := range removed {
		if o.json {
			printEachJSON(stdout, d, "removed", nil)
			continue
		}
		fmt.Fprintln(stdout, termsafe.Escape(d+": removed by this change, but its resources are still in its state; destroy them from "+o.changed+" first, or move them"))
	}
	switch {
	case failed:
		return 1
	case changes && o.detailedExitcode:
		return 2
	}
	return 0
}

// workFile reports whether p is something init, plan or apply writes on
// their own, which says nothing about what changed: anything under
// .terraform, local state and its backup and lock. A lock file new to the
// tree counts only once committed, since init writes one.
func workFile(p string) bool {
	base := path.Base(p)
	return strings.Contains("/"+p, "/.terraform/") ||
		strings.HasSuffix(base, ".tfstate") || strings.HasSuffix(base, ".tfstate.backup") ||
		base == ".terraform.tfstate.lock.info"
}

// gitChanges lists the files changed since ref, relative to root: commits
// since ref, uncommitted edits and new files git doesn't ignore. gone are
// the directories, relative to root, that held a deleted .tf or
// .circuit.hcl file.
func gitChanges(root, ref string) (files, gone []string, err error) {
	git := func(args ...string) ([]string, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(errOut.String()))
		}
		var lines []string
		for _, l := range strings.Split(out.String(), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				lines = append(lines, l)
			}
		}
		return lines, nil
	}
	top, err := git("rev-parse", "--show-toplevel")
	if err != nil {
		return nil, nil, err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, nil, err
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	here, err := filepath.Rel(top[0], abs)
	if err != nil {
		return nil, nil, err
	}
	here = filepath.ToSlash(here)
	// Paths from git are relative to the top of the repository.
	rel := func(p string) string {
		if here == "." {
			return p
		}
		r, err := filepath.Rel(here, p)
		if err != nil {
			return p
		}
		return filepath.ToSlash(r)
	}
	seen := map[string]bool{}
	for _, args := range [][]string{
		// --no-renames: a moved file is a delete in one place and an add in
		// another, and the configuration it left changed as much as the one
		// it went to.
		{"diff", "--name-only", "--no-renames", ref + "...HEAD"},
		{"diff", "--name-only", "--no-renames", "HEAD"},
		{"ls-files", "--others", "--exclude-standard", "--full-name"},
	} {
		lines, err := git(args...)
		if err != nil {
			return nil, nil, err
		}
		if args[0] == "ls-files" {
			lines = slices.DeleteFunc(lines, func(l string) bool { return path.Base(l) == ".terraform.lock.hcl" })
		}
		for _, l := range lines {
			if workFile(l) {
				continue
			}
			if r := rel(l); !seen[r] {
				seen[r] = true
				files = append(files, r)
			}
		}
	}
	var deleted []string
	for _, base := range []string{ref + "...HEAD", "HEAD"} { // committed, and not yet
		lines, err := git("diff", "--name-only", "--no-renames", "--diff-filter=D", base)
		if err != nil {
			return nil, nil, err
		}
		deleted = append(deleted, lines...)
	}
	dirs := map[string]bool{}
	for _, l := range deleted {
		if strings.HasSuffix(l, ".tf") || strings.HasSuffix(l, ".tofu") || strings.HasSuffix(l, ".circuit.hcl") {
			dirs[path.Dir(rel(l))] = true
		}
	}
	for d := range dirs {
		gone = append(gone, d)
	}
	sort.Strings(files)
	sort.Strings(gone)
	return files, gone, nil
}

// changeCounts is a plan's -json change summary, without its operation.
type changeCounts struct {
	Add    int `json:"add"`
	Change int `json:"change"`
	Import int `json:"import"`
	Remove int `json:"remove"`
	Forget int `json:"forget"`
}

// planChanges reads the change_summary message from a plan's -json
// stream, or nil when there's none.
func planChanges(out []byte) *changeCounts {
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var m struct {
			Type    string        `json:"type"`
			Changes *changeCounts `json:"changes"`
		}
		if json.Unmarshal(sc.Bytes(), &m) == nil && m.Type == "change_summary" && m.Changes != nil {
			return m.Changes
		}
	}
	return nil
}

// printEachJSON prints one configuration's result as -json does: the
// text summary's word, with "because" for a skip and "changes" for a plan
// that has some.
func printEachJSON(w io.Writer, dir, r string, c *changeCounts) {
	obj := map[string]any{"dir": dir}
	switch {
	case strings.HasPrefix(r, "skipped: "):
		obj["result"] = "skipped"
		obj["because"] = strings.TrimSuffix(strings.TrimPrefix(r, "skipped: "), " didn't plan")
	case strings.HasPrefix(r, "not run"):
		obj["result"] = "not run"
	default:
		obj["result"] = r
	}
	if c != nil {
		obj["changes"] = c
	}
	line, _ := json.Marshal(obj)
	fmt.Fprintln(w, string(line))
}
