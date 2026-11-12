// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/afero"
	cli "github.com/urfave/cli/v3"

	"github.com/opentofu/opentofu/internal/addrs"
	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/command/arguments"
	"github.com/opentofu/opentofu/internal/configs"
	runreport "github.com/opentofu/opentofu/internal/conn3x/report"
	"github.com/opentofu/opentofu/internal/plans"
)

const (
	batchSizeHelp   = `Roll the batched circuit out this many hosts at a time, or this percentage of the hosts that change, such as "20%". Overrides the circuit's batch_size for this run.`
	maxFailuresHelp = `How many hosts may fail before no more batches start. Overrides the circuit's max_failures for this run.`

	// batchCircuitEnv narrows a batch's -limit to the circuit rolling out
	// (see tofu.Conn3xCLILimitCircuit).
	batchCircuitEnv = "CONN3X_BATCH_CIRCUIT"
)

// withBatch makes apply roll a circuit with batch_size out batch by batch,
// as Ansible's serial does: it plans everything and asks once, then plans
// and applies each batch of hosts with -limit, and stops starting batches
// once more hosts have failed than max_failures allows. It runs conn3x
// again for each plan and apply, as drift does.
func withBatch(cmd *command.Command) {
	var size string
	maxFailures := -1
	cmd.CommandLine.StringVar(&size, "batch-size", "", batchSizeHelp).SetDisplay("=n")
	cmd.CommandLine.IntVar(&maxFailures, "max-failures", -1, maxFailuresHelp).SetDisplay("=n")
	var planPath *string
	for _, a := range cmd.CommandLine.Args {
		if s, ok := a.Cli.(*cli.StringArg); ok && a.Name == "PLAN" {
			planPath = s.Destination
		}
	}
	op, view := cmd.CommandLine.Operation, cmd.CommandLine.View
	run := cmd.Run
	cmd.Run = func(m command.Meta) int {
		batches, diags := configs.Conn3xBatches(".")
		if planPath != nil && *planPath != "" && size == "" && maxFailures < 0 {
			return run(m) // a saved plan was planned whole, and applies whole
		}
		if diags.HasErrors() {
			return run(m) // the configuration's own load reports it
		}
		if len(batches) == 0 {
			if size != "" || maxFailures >= 0 {
				fmt.Fprintln(stderr, "Error: -batch-size and -max-failures need a circuit with batch_size")
				return 1
			}
			return run(m)
		}
		bs, err := batchesFor(batches, size, maxFailures)
		args := os.Args[1:]
		if err == nil {
			err = batchRefuses(args, planPath, op, view)
		}
		if err == nil {
			err = limitReachesPlan(m, nil)
		}
		if err != nil {
			fmt.Fprintf(stderr, "Error: %s\n", err)
			return 1
		}
		self, err := os.Executable()
		if err != nil {
			fmt.Fprintf(stderr, "Error: finding the conn3x binary: %s\n", err)
			return 1
		}
		tmp, err := os.MkdirTemp("", "conn3x-batch-*")
		if err != nil {
			fmt.Fprintf(stderr, "Error: %s\n", err)
			return 1
		}
		defer os.RemoveAll(tmp)
		r := &batchRun{self: self, dir: m.WorkingDir.OriginalWorkingDir(), tmp: tmp, args: args, out: stdout, errOut: stderr, in: os.Stdin, hosts: moduleStepHosts(".")}
		r.reportPath, _ = flagValue(r.applyFlags(), "report")
		started := time.Now()
		code := r.apply(bs)
		if r.reportPath != "" {
			if err := r.writeReport(started, code == 0); err != nil {
				fmt.Fprintf(stderr, "Error: writing the report: %s\n", err)
				return 1
			}
		}
		return code
	}
}

// batchesFor applies the flags to every batched circuit.
func batchesFor(batches []configs.Conn3xBatch, size string, maxFailures int) ([]configs.Conn3xBatch, error) {
	out := slices.Clone(batches)
	for i := range out {
		if size != "" {
			var err error
			if out[i].Size, out[i].Percent, err = configs.ParseConn3xBatchSize(size); err != nil {
				return nil, fmt.Errorf("-batch-size: %s", err)
			}
		}
		if maxFailures >= 0 {
			out[i].MaxFailures = maxFailures
		}
	}
	return out, nil
}

// batchRefuses refuses what a batched apply can't honour.
func batchRefuses(args []string, planPath *string, op *arguments.Operation, view *arguments.View) error {
	switch {
	case planPath != nil && *planPath != "":
		return fmt.Errorf("a saved plan applies whole; -batch-size and -max-failures can't split it")
	case op != nil && op.PlanMode == plans.DestroyMode:
		return fmt.Errorf("a destroy doesn't run in batches; take batch_size off the circuit, or remove hosts from its hosts and apply")
	case op != nil && (len(op.Targets) > 0 || len(op.Excludes) > 0):
		return fmt.Errorf("a batched apply picks its own hosts, so it can't take -target or -exclude")
	case view != nil && view.ViewType == arguments.ViewJSON:
		return fmt.Errorf("a batched apply has no -json output yet")
	}
	for _, name := range []string{"json-into"} {
		if _, ok := flagValue(args, name); ok {
			return fmt.Errorf("a batched apply can't take -%s yet", name)
		}
	}
	return nil
}

// flagValue finds -name or -name=value in args, with one or two dashes.
func flagValue(args []string, name string) (string, bool) {
	for _, a := range args {
		a = strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-")
		if a == name {
			return "", true
		}
		if v, ok := strings.CutPrefix(a, name+"="); ok {
			return v, true
		}
	}
	return "", false
}

type batchRun struct {
	self, dir, tmp string
	args           []string // conn3x's arguments, global options and apply's
	out, errOut    io.Writer
	in             io.Reader
	hosts          stepHosts
	runs           int
	reportPath     string        // -report, or ""
	streams        []batchStream // each batch apply's -json-into, for the report
	errors         []string      // what the rollout said went wrong, for the report
}

type batchStream struct {
	path string
	ok   bool
}

// rollout is one batched circuit's hosts, cut into batches.
type rollout struct {
	configs.Conn3xBatch
	size    int
	batches [][]string
}

// apply plans everything, asks, and rolls each batched circuit out in
// turn, in the order their dependencies give.
func (r *batchRun) apply(bs []configs.Conn3xBatch) int {
	whole, code := r.plan(nil, "", r.out)
	if code != 2 {
		return code // failed, or nothing to change
	}
	bs, err := whole.ordered(bs)
	if err != nil {
		r.errorf("%s", err)
		return 1
	}
	var rollouts []rollout
	total := 0
	for _, b := range bs {
		hosts, _ := whole.circuitHosts(b.Circuit, r.hosts)
		if len(hosts) == 0 {
			continue
		}
		ro := rollout{Conn3xBatch: b, size: b.Of(len(hosts))}
		for chunk := range slices.Chunk(hosts, ro.size) {
			ro.batches = append(ro.batches, chunk)
		}
		rollouts = append(rollouts, ro)
		total += len(ro.batches)
	}
	if len(rollouts) == 0 {
		// No batched circuit changes, so the rest applies in one go, once
		// approved like any apply.
		if !r.approved("") {
			fmt.Fprintln(r.errOut, "\nApply cancelled.")
			return 1
		}
		return r.applyPlan(whole.path)
	}
	// Everything else applies first, in one go, so long as none of it needs
	// a batched circuit's steps.
	var first *batchPlan
	if others := whole.outside(bs); len(others) > 0 {
		if first, code = r.planFirst(whole, bs, others); code == 1 {
			return 1
		}
		if first != nil {
			fmt.Fprintf(r.out, "\nFirst, %d other %s in one go:\n  %s\n", len(others), plural(len(others), "change applies", "changes apply"), strings.Join(others, "\n  "))
		}
	}
	for _, ro := range rollouts {
		hosts := 0
		for _, batch := range ro.batches {
			hosts += len(batch)
		}
		fmt.Fprintf(r.out, "\nCircuit %q changes %d %s, which roll out in %d %s of up to %d. No more batches start once more than %d %s failed.\n",
			ro.Circuit, hosts, plural(hosts, "host", "hosts"), len(ro.batches), plural(len(ro.batches), "batch", "batches"), ro.size, ro.MaxFailures, plural(ro.MaxFailures, "host has", "hosts have"))
	}
	if len(rollouts) > 1 {
		fmt.Fprintln(r.out, "\nEach circuit rolls out after the one before it, in this order.")
	}
	if !r.approved(" in batches") {
		fmt.Fprintln(r.errOut, "\nApply cancelled.")
		return 1
	}
	if first != nil {
		fmt.Fprintln(r.out, "\nThe other changes:")
		if r.applyPlan(first.path) != 0 {
			r.errorf("the changes outside the batched circuits failed, so no batch starts.")
			return 1
		}
	}

	for i, ro := range rollouts {
		var later []string
		for _, rest := range rollouts[i+1:] {
			later = append(later, fmt.Sprintf("%q", rest.Circuit))
		}
		failed, ok := r.rollOut(whole, ro, len(rollouts) > 1, later)
		if !ok {
			return 1
		}
		if len(failed) > 0 {
			msg := fmt.Sprintf("every batch ran, and %d %s failed, within max_failures = %d.\n  Failed: %s", len(failed), plural(len(failed), "host", "hosts"), ro.MaxFailures, strings.Join(failed, ", "))
			if len(later) > 0 {
				msg = fmt.Sprintf("every batch of circuit %q ran, and %d %s failed, within max_failures = %d.\n  Failed: %s\n  Not started, since they may depend on the failed hosts: %s %s", ro.Circuit, len(failed), plural(len(failed), "host", "hosts"), ro.MaxFailures, strings.Join(failed, ", "), plural(len(later), "circuit", "circuits"), strings.Join(later, ", "))
			}
			r.errorf("%s", msg)
			return 1
		}
	}
	fmt.Fprintf(r.out, "\nAll %d %s applied.\n", total, plural(total, "batch", "batches"))
	return 0
}

// planFirst plans the changes outside bs's circuits with -target, to apply
// before the rollout. It refuses, with code 1, when they need a batched
// circuit's steps: -target brings a target's dependencies along. A nil plan
// with code 0 means there was nothing to change after all.
func (r *batchRun) planFirst(whole *batchPlan, bs []configs.Conn3xBatch, others []string) (*batchPlan, int) {
	targets := make([]string, len(others))
	for i, o := range others {
		targets[i] = "-target=" + o
	}
	var planOut bytes.Buffer
	plan, code := r.plan(nil, "", &planOut, targets...)
	if code == 1 {
		_, _ = io.Copy(r.errOut, &planOut)
		return nil, 1
	}
	if code == 0 {
		return nil, 0
	}
	if extra := plan.notIn(whole); len(extra) > 0 {
		r.errorf("the plan for the changes outside the batched circuits has changes the approved plan didn't:\n  %s\nSomething changed since the plan; run the apply again to see it.", strings.Join(extra, "\n  "))
		return nil, 1
	}
	outside := plan.outside(bs)
	var steps []string
	for _, c := range plan.changes {
		if c.changes() && !slices.Contains(outside, c.addr) {
			steps = append(steps, c.addr)
		}
	}
	if len(steps) > 0 {
		r.errorf("this plan changes resources outside the batched circuits that need batched steps first:\n  %s\nSo they can't apply before the rollout, and the steps can't apply all at once. Apply them after the rollout with -target, or take batch_size off.", strings.Join(steps, "\n  "))
		return nil, 1
	}
	return plan, 2
}

// rollOut applies ro batch by batch. It returns the hosts that failed
// within max_failures, and false once the rollout must stop, having said
// why.
func (r *batchRun) rollOut(whole *batchPlan, ro rollout, named bool, later []string) ([]string, bool) {
	var failed []string
	for i, batch := range ro.batches {
		if named {
			fmt.Fprintf(r.out, "\nCircuit %q, batch %d of %d: %s\n", ro.Circuit, i+1, len(ro.batches), strings.Join(batch, ", "))
		} else {
			fmt.Fprintf(r.out, "\nBatch %d of %d: %s\n", i+1, len(ro.batches), strings.Join(batch, ", "))
		}
		var planOut bytes.Buffer
		plan, code := r.plan(batch, ro.Circuit, &planOut)
		if code == 0 {
			fmt.Fprintln(r.out, "Nothing left to change on these hosts.")
			continue
		}
		if code == 1 {
			_, _ = io.Copy(r.errOut, &planOut)
			return nil, false
		}
		if extra := plan.notIn(whole); len(extra) > 0 {
			r.errorf("batch %d's plan has changes the approved plan didn't:\n  %s\nSomething changed since the plan; run the apply again to see it.", i+1, strings.Join(extra, "\n  "))
			return nil, false
		}
		// A step that depends on another batched circuit's would bring its
		// changes along; ordered puts that circuit first, so this is a check.
		if others := plan.outside([]configs.Conn3xBatch{ro.Conn3xBatch}); len(others) > 0 {
			r.errorf("batch %d's plan changes more than circuit %q:\n  %s\nApply those first, with -target or without batch_size.", i+1, ro.Circuit, strings.Join(others, "\n  "))
			return nil, false
		}
		if r.applyPlan(plan.path) == 0 {
			continue
		}
		// What's still to change on the batch's hosts is what failed there.
		left, code := r.plan(batch, ro.Circuit, io.Discard)
		if code == 1 {
			r.errorf("batch failed, and the plan to see which hosts failed did too. No more batches start.")
			return nil, false
		}
		if left != nil { // nil when nothing is left: what failed wasn't a step
			batchFailed, _ := left.circuitHosts(ro.Circuit, r.hosts)
			failed = append(failed, batchFailed...)
		}
		if len(failed) > ro.MaxFailures {
			var notReached []string
			for _, rest := range ro.batches[i+1:] {
				notReached = append(notReached, rest...)
			}
			msg := fmt.Sprintf("%d %s failed, more than max_failures = %d, so no more batches start.\n  Failed: %s", len(failed), plural(len(failed), "host", "hosts"), ro.MaxFailures, strings.Join(failed, ", "))
			if len(notReached) > 0 {
				msg += "\n  Not reached: " + strings.Join(notReached, ", ")
			}
			if len(later) > 0 {
				msg += fmt.Sprintf("\n  Not started: %s %s", plural(len(later), "circuit", "circuits"), strings.Join(later, ", "))
			}
			r.errorf("%s", msg)
			return nil, false
		}
	}
	return failed, true
}

// errorf says what went wrong with the rollout, and keeps it for the report.
func (r *batchRun) errorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(r.errOut, "\nError: %s\n", msg)
	r.errors = append(r.errors, "Error: "+msg)
}

// applyPlan applies a saved plan, keeping its JSON stream when there's a
// report to write.
func (r *batchRun) applyPlan(plan string) int {
	args := r.applyArgs(plan)
	if r.reportPath != "" {
		stream := filepath.Join(r.tmp, fmt.Sprintf("apply-%d.jsonl", len(r.streams)+1))
		args = append(args[:len(args)-1], "-json-into="+stream, plan)
		code := r.run(args, r.out)
		r.streams = append(r.streams, batchStream{path: stream, ok: code == 0})
		return code
	}
	return r.run(args, r.out)
}

// writeReport writes one report for the whole rollout, from every batch's
// apply: a host from a batch that never started isn't in it, and the
// rollout's own errors say which those were.
func (r *batchRun) writeReport(started time.Time, success bool) error {
	rep := runreport.New("apply", started)
	for _, s := range r.streams {
		in, err := os.Open(s.path)
		if err != nil {
			return err
		}
		err = rep.FromApply(in, s.ok)
		_ = in.Close()
		if _, long := err.(runreport.LongLines); err != nil && !long {
			return err
		}
	}
	rep.Success = success
	rep.Errors = append(rep.Errors, r.errors...)
	return writeReport(r.reportPath, rep)
}

// approved asks before applying anything, unless -auto-approve says yes.
// how is how the actions apply, such as " in batches".
func (r *batchRun) approved(how string) bool {
	if _, ok := flagValue(r.applyFlags(), "auto-approve"); ok {
		return true
	}
	if v, ok := flagValue(r.applyFlags(), "input"); ok && v == "false" {
		fmt.Fprintf(r.errOut, "\nError: -input=false needs -auto-approve to apply%s.\n", how)
		return false
	}
	fmt.Fprintf(r.out, "\nDo you want to perform these actions%s?\n  Only 'yes' will be accepted to approve.\n\n  Enter a value: ", how)
	line, _ := bufio.NewReader(r.in).ReadString('\n')
	return strings.TrimSpace(line) == "yes"
}

// split cuts conn3x's arguments at the apply subcommand.
func (r *batchRun) split() (global, apply []string) {
	i := slices.Index(r.args, "apply")
	return r.args[:i], r.args[i+1:]
}

// applyFlags is apply's own arguments, less the batching flags.
func (r *batchRun) applyFlags() []string {
	_, apply := r.split()
	var out []string
	for i := 0; i < len(apply); i++ {
		a := strings.TrimPrefix(strings.TrimPrefix(apply[i], "-"), "-")
		switch {
		case a == "batch-size" || a == "max-failures":
			i++ // and its value
		case strings.HasPrefix(a, "batch-size=") || strings.HasPrefix(a, "max-failures="):
		default:
			out = append(out, apply[i])
		}
	}
	return out
}

// planArgs is a plan with the apply's options, limited to hosts if any.
func (r *batchRun) planArgs(hosts []string, out string) []string {
	global, _ := r.split()
	args := append(slices.Clone(global), "plan", "-detailed-exitcode", "-out="+out)
	flags := withoutFlag(r.applyFlags(), "report") // the rollout writes one
	if hosts != nil {
		// A batch's hosts are already inside any -limit the apply was given.
		// shortcut: host names go in as patterns, so one holding * ? [ or
		// a separator would match more or fewer; quote them if that comes up.
		args = append(args, "-limit="+strings.Join(hosts, ","))
		flags = withoutFlag(flags, "limit")
	}
	return append(args, slices.DeleteFunc(flags, func(a string) bool {
		_, auto := flagValue([]string{a}, "auto-approve")
		return auto
	})...)
}

// withoutFlag drops -name and its value, in either form, from args.
func withoutFlag(args []string, name string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := strings.TrimPrefix(strings.TrimPrefix(args[i], "-"), "-")
		switch {
		case a == name:
			i++ // and its value
		case strings.HasPrefix(a, name+"="):
		default:
			out = append(out, args[i])
		}
	}
	return out
}

// applyArgs applies a saved plan, with the apply options a saved plan takes.
func (r *batchRun) applyArgs(plan string) []string {
	global, _ := r.split()
	args := append(slices.Clone(global), "apply")
	for _, a := range r.applyFlags() {
		name, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-"), "=")
		switch name {
		case "no-color", "parallelism", "lock", "lock-timeout", "compact-warnings", "concise", "show-sensitive":
			args = append(args, a)
		}
	}
	return append(args, plan)
}

// plan runs a plan, limited to circuit's steps on hosts if any, with extra
// arguments, shows it on out, and reads it back. Its code is plan
// -detailed-exitcode's: 0 for no changes, 2 for changes, 1 for errors.
func (r *batchRun) plan(hosts []string, circuit string, out io.Writer, extra ...string) (*batchPlan, int) {
	r.runs++
	path := filepath.Join(r.tmp, fmt.Sprintf("plan-%d.tfplan", r.runs))
	args := r.planArgs(hosts, path)
	if len(extra) > 0 {
		args = withoutFlag(args, "limit") // -target and -limit don't mix
	}
	code := r.run(append(args, extra...), out, batchCircuitEnv+"="+circuit)
	if code != 2 {
		return nil, code
	}
	global, _ := r.split()
	var js bytes.Buffer
	show := exec.Command(r.self, append(slices.Clone(global), "show", "-json", path)...)
	show.Dir, show.Stdout, show.Stderr = r.dir, &js, r.errOut
	if err := show.Run(); err != nil {
		fmt.Fprintf(r.errOut, "Error: reading the plan back: %s\n", err)
		return nil, 1
	}
	p, err := readBatchPlan(js.Bytes())
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: reading the plan back: %s\n", err)
		return nil, 1
	}
	p.path = path
	return p, 2
}

// run runs conn3x with args, and env added to its environment, and returns
// its exit code.
func (r *batchRun) run(args []string, out io.Writer, env ...string) int {
	c := exec.Command(r.self, args...)
	c.Dir, c.Stdout, c.Stderr, c.Stdin = r.dir, out, r.errOut, r.in
	if out != r.out {
		c.Stderr = out // a batch's plan shows its errors only if it fails
	}
	// No "run conn3x apply" hints between batches.
	c.Env = append(append(os.Environ(), "TF_IN_AUTOMATION=1"), env...)
	if err := c.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode()
		}
		fmt.Fprintf(r.errOut, "Error: running conn3x: %s\n", err)
		return 1
	}
	return 0
}

// batchPlan is what a batched apply reads from a plan.
type batchPlan struct {
	path    string
	changes []batchChange
	deps    map[string][]string // each root module resource's references and depends_on
}

type batchChange struct {
	addr, module, typ, name string
	key                     any
	actions                 string
}

func readBatchPlan(js []byte) (*batchPlan, error) {
	var raw struct {
		ResourceChanges []struct {
			Address       string `json:"address"`
			ModuleAddress string `json:"module_address"`
			Mode          string `json:"mode"`
			Type          string `json:"type"`
			Name          string `json:"name"`
			Index         any    `json:"index"`
			Change        struct {
				Actions []string `json:"actions"`
			} `json:"change"`
		} `json:"resource_changes"`
		Configuration struct {
			RootModule struct {
				Resources []struct {
					Address     string   `json:"address"`
					DependsOn   []string `json:"depends_on"`
					Expressions any      `json:"expressions"`
				} `json:"resources"`
			} `json:"root_module"`
		} `json:"configuration"`
	}
	if err := json.Unmarshal(js, &raw); err != nil {
		return nil, err
	}
	p := &batchPlan{deps: map[string][]string{}}
	for _, r := range raw.Configuration.RootModule.Resources {
		p.deps[r.Address] = append(slices.Clone(r.DependsOn), references(r.Expressions)...)
	}
	for _, c := range raw.ResourceChanges {
		if c.Mode != "managed" {
			continue
		}
		p.changes = append(p.changes, batchChange{addr: c.Address, module: c.ModuleAddress, typ: c.Type, name: c.Name, key: c.Index, actions: strings.Join(c.Change.Actions, ",")})
	}
	return p, nil
}

// references lists the resource addresses in a plan's JSON expressions,
// without instance keys or attributes.
func references(v any) []string {
	var out []string
	switch v := v.(type) {
	case map[string]any:
		for k, e := range v {
			refs, ok := e.([]any)
			if k != "references" || !ok {
				out = append(out, references(e)...)
				continue
			}
			for _, ref := range refs {
				s, _ := ref.(string)
				parts := strings.Split(s, ".")
				n := 2
				if parts[0] == "data" {
					n = 3
				}
				if len(parts) >= n {
					parts[n-1], _, _ = strings.Cut(parts[n-1], "[")
					out = append(out, strings.Join(parts[:n], "."))
				}
			}
		}
	case []any:
		for _, e := range v {
			out = append(out, references(e)...)
		}
	}
	return out
}

// ordered puts bs in the order their dependencies give: a circuit whose
// steps depend on another's, directly or through other resources, comes
// after it. Circuits that don't depend on each other keep bs's order.
// shortcut: a dependency through a local value or a module isn't seen;
// the batch plans' outside check catches it.
func (p *batchPlan) ordered(bs []configs.Conn3xBatch) ([]configs.Conn3xBatch, error) {
	circuitOf := func(addr string) string {
		typ, name, _ := strings.Cut(addr, ".")
		for _, b := range bs {
			if strings.HasPrefix(typ, "conn3x_") && strings.HasPrefix(name, b.Circuit+"__") {
				return b.Circuit
			}
		}
		return ""
	}
	after := map[string]map[string]bool{} // circuit to the circuits it depends on
	for addr := range p.deps {
		c := circuitOf(addr)
		if c == "" {
			continue
		}
		seen := map[string]bool{addr: true}
		stack := slices.Clone(p.deps[addr])
		for len(stack) > 0 {
			d := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if seen[d] {
				continue
			}
			seen[d] = true
			if dc := circuitOf(d); dc != "" && dc != c {
				if after[c] == nil {
					after[c] = map[string]bool{}
				}
				after[c][dc] = true
			}
			stack = append(stack, p.deps[d]...)
		}
	}
	var out []configs.Conn3xBatch
	done := map[string]bool{}
	for len(out) < len(bs) {
		next := slices.IndexFunc(bs, func(b configs.Conn3xBatch) bool {
			if done[b.Circuit] {
				return false
			}
			for dep := range after[b.Circuit] {
				if !done[dep] {
					return false
				}
			}
			return true
		})
		if next < 0 {
			var left []string
			for _, b := range bs {
				if !done[b.Circuit] {
					left = append(left, fmt.Sprintf("%q", b.Circuit))
				}
			}
			return nil, fmt.Errorf("circuits %s depend on each other, so none of them can roll out first. Apply them one at a time with -target, or take batch_size off all but one", strings.Join(left, ", "))
		}
		done[bs[next].Circuit] = true
		out = append(out, bs[next])
	}
	return out, nil
}

// outside lists p's changes to anything but bs's circuits' steps.
func (p *batchPlan) outside(bs []configs.Conn3xBatch) []string {
	var out []string
	for _, c := range p.changes {
		if !c.changes() {
			continue
		}
		if _, ok := c.key.(string); !ok || c.module != "" || !slices.ContainsFunc(bs, func(b configs.Conn3xBatch) bool { return strings.HasPrefix(c.name, b.Circuit+"__") }) {
			out = append(out, c.addr)
		}
	}
	return out
}

func (c batchChange) changes() bool { return c.actions != "no-op" && c.actions != "read" }

// stepHosts lists the hosts a root module step instance's key may belong
// to, from the configuration; nil when it doesn't know the step.
type stepHosts func(typ, name, key string) []string

// moduleStepHosts reads the root module in dir for stepHosts.
func moduleStepHosts(dir string) stepHosts {
	mod, _ := configs.NewParser(afero.NewOsFs()).LoadConfigDir(dir)
	if mod == nil {
		return nil
	}
	return func(typ, name, key string) []string {
		r := mod.ManagedResources[typ+"."+name]
		if r == nil {
			return nil
		}
		return configs.Conn3xStepHosts(r, addrs.StringKey(key))
	}
}

// circuitHosts lists, in name order, the hosts with changes to circuit's
// steps, and the other changes the plan makes.
func (p *batchPlan) circuitHosts(circuit string, of stepHosts) (hosts, others []string) {
	candidates := func(c batchChange, key string) []string {
		if of != nil {
			if hs := of(c.typ, c.name, key); len(hs) > 0 {
				return hs
			}
		}
		// Not in the configuration it read: a looping step's key is
		// host/item, so take every reading of it.
		var hs []string
		for i := range len(key) {
			if key[i] == '/' {
				hs = append(hs, key[:i])
			}
		}
		return append(hs, key)
	}
	inCircuit := func(c batchChange) (string, bool) {
		k, ok := c.key.(string)
		return k, ok && c.module == "" && strings.HasPrefix(c.name, circuit+"__")
	}
	known := map[string]bool{} // keys that are host names: a step that doesn't loop has them
	for _, c := range p.changes {
		if k, ok := inCircuit(c); ok {
			if hs := candidates(c, k); len(hs) == 1 && hs[0] == k {
				known[k] = true
			}
		}
	}
	seen := map[string]bool{}
	for _, c := range p.changes {
		if !c.changes() {
			continue
		}
		k, ok := inCircuit(c)
		if !ok {
			others = append(others, c.addr)
			continue
		}
		hs := candidates(c, k)
		h := hs[0]
		for _, cand := range hs {
			if known[cand] {
				h = cand // the longest reading that names a host
			}
		}
		if !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	slices.SortFunc(hosts, naturalCompare)
	return hosts, others
}

// notIn lists p's changes that approved doesn't make the same way.
func (p *batchPlan) notIn(approved *batchPlan) []string {
	want := map[string]string{}
	for _, c := range approved.changes {
		want[c.addr] = c.actions
	}
	var extra []string
	for _, c := range p.changes {
		if c.changes() && want[c.addr] != c.actions {
			extra = append(extra, c.addr)
		}
	}
	return extra
}

// naturalCompare orders web2 before web10.
func naturalCompare(a, b string) int {
	for a != "" && b != "" {
		da, db := digitsPrefix(a), digitsPrefix(b)
		if da != "" && db != "" {
			na, _ := strconv.ParseUint(da, 10, 64)
			nb, _ := strconv.ParseUint(db, 10, 64)
			if na != nb {
				if na < nb {
					return -1
				}
				return 1
			}
			a, b = a[len(da):], b[len(db):]
			continue
		}
		if a[0] != b[0] {
			if a[0] < b[0] {
				return -1
			}
			return 1
		}
		a, b = a[1:], b[1:]
	}
	return len(a) - len(b)
}

func digitsPrefix(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
