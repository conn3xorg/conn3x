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

	"github.com/spf13/afero"
	cli "github.com/urfave/cli/v3"

	"github.com/opentofu/opentofu/internal/addrs"
	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/command/arguments"
	"github.com/opentofu/opentofu/internal/configs"
	"github.com/opentofu/opentofu/internal/plans"
)

const (
	batchSizeHelp   = `Roll the batched circuit out this many hosts at a time, or this percentage of the hosts that change, such as "20%". Overrides the circuit's batch_size for this run.`
	maxFailuresHelp = `How many hosts may fail before no more batches start. Overrides the circuit's max_failures for this run.`
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
		b, err := batchFor(batches, size, maxFailures)
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
		return r.apply(b)
	}
}

// batchFor picks the batched circuit and applies the flags to it.
func batchFor(batches []configs.Conn3xBatch, size string, maxFailures int) (configs.Conn3xBatch, error) {
	if len(batches) > 1 {
		names := make([]string, len(batches))
		for i, b := range batches {
			names[i] = b.Circuit
		}
		return configs.Conn3xBatch{}, fmt.Errorf("circuits %s all have batch_size; one apply rolls out one batched circuit. Apply them one at a time with -target, or take batch_size off all but one", strings.Join(names, ", "))
	}
	b := batches[0]
	if size != "" {
		var err error
		if b.Size, b.Percent, err = configs.ParseConn3xBatchSize(size); err != nil {
			return b, fmt.Errorf("-batch-size: %s", err)
		}
	}
	if maxFailures >= 0 {
		b.MaxFailures = maxFailures
	}
	return b, nil
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
	for _, name := range []string{"limit", "report", "json-into"} {
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
}

// apply plans everything, asks, and rolls b out.
func (r *batchRun) apply(b configs.Conn3xBatch) int {
	whole, code := r.plan(nil, r.out)
	if code != 2 {
		return code // failed, or nothing to change
	}
	hosts, others := whole.circuitHosts(b.Circuit, r.hosts)
	if len(hosts) == 0 {
		return r.run(r.applyArgs(whole.path), r.out) // only outputs change
	}
	if len(others) > 0 {
		fmt.Fprintf(r.errOut, "\nError: a batched apply changes only circuit %q, and this plan also changes:\n  %s\nApply those first, with -target or without batch_size.\n", b.Circuit, strings.Join(others, "\n  "))
		return 1
	}
	size := b.Of(len(hosts))
	var batches [][]string
	for chunk := range slices.Chunk(hosts, size) {
		batches = append(batches, chunk)
	}
	fmt.Fprintf(r.out, "\nCircuit %q changes %d %s, which roll out in %d %s of up to %d. No more batches start once more than %d %s failed.\n",
		b.Circuit, len(hosts), plural(len(hosts), "host", "hosts"), len(batches), plural(len(batches), "batch", "batches"), size, b.MaxFailures, plural(b.MaxFailures, "host has", "hosts have"))
	if !r.approved() {
		fmt.Fprintln(r.errOut, "\nApply cancelled.")
		return 1
	}

	var failed []string
	for i, batch := range batches {
		fmt.Fprintf(r.out, "\nBatch %d of %d: %s\n", i+1, len(batches), strings.Join(batch, ", "))
		var planOut bytes.Buffer
		plan, code := r.plan(batch, &planOut)
		if code == 0 {
			fmt.Fprintln(r.out, "Nothing left to change on these hosts.")
			continue
		}
		if code == 1 {
			_, _ = io.Copy(r.errOut, &planOut)
			return 1
		}
		if extra := plan.notIn(whole); len(extra) > 0 {
			fmt.Fprintf(r.errOut, "\nError: batch %d's plan has changes the approved plan didn't:\n  %s\nSomething changed since the plan; run the apply again to see it.\n", i+1, strings.Join(extra, "\n  "))
			return 1
		}
		if r.run(r.applyArgs(plan.path), r.out) == 0 {
			continue
		}
		// What's still to change on the batch's hosts is what failed there.
		left, code := r.plan(batch, io.Discard)
		if code == 1 {
			fmt.Fprintln(r.errOut, "\nError: batch failed, and the plan to see which hosts failed did too. No more batches start.")
			return 1
		}
		if left != nil { // nil when nothing is left: what failed wasn't a step
			batchFailed, _ := left.circuitHosts(b.Circuit, r.hosts)
			failed = append(failed, batchFailed...)
		}
		if len(failed) > b.MaxFailures {
			var notReached []string
			for _, rest := range batches[i+1:] {
				notReached = append(notReached, rest...)
			}
			fmt.Fprintf(r.errOut, "\nError: %d %s failed, more than max_failures = %d, so no more batches start.\n  Failed: %s\n", len(failed), plural(len(failed), "host", "hosts"), b.MaxFailures, strings.Join(failed, ", "))
			if len(notReached) > 0 {
				fmt.Fprintf(r.errOut, "  Not reached: %s\n", strings.Join(notReached, ", "))
			}
			return 1
		}
	}
	if len(failed) > 0 {
		fmt.Fprintf(r.errOut, "\nError: every batch ran, and %d %s failed, within max_failures = %d.\n  Failed: %s\n", len(failed), plural(len(failed), "host", "hosts"), b.MaxFailures, strings.Join(failed, ", "))
		return 1
	}
	fmt.Fprintf(r.out, "\nAll %d %s applied.\n", len(batches), plural(len(batches), "batch", "batches"))
	return 0
}

// approved asks before the first batch, unless -auto-approve says yes.
func (r *batchRun) approved() bool {
	if _, ok := flagValue(r.applyFlags(), "auto-approve"); ok {
		return true
	}
	if v, ok := flagValue(r.applyFlags(), "input"); ok && v == "false" {
		fmt.Fprintln(r.errOut, "\nError: -input=false needs -auto-approve to apply in batches.")
		return false
	}
	fmt.Fprint(r.out, "\nDo you want to perform these actions in batches?\n  Only 'yes' will be accepted to approve.\n\n  Enter a value: ")
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
	if hosts != nil {
		// shortcut: host names go in as patterns, so one holding * ? [ or
		// a separator would match more or fewer; quote them if that comes up.
		args = append(args, "-limit="+strings.Join(hosts, ","))
	}
	return append(args, slices.DeleteFunc(r.applyFlags(), func(a string) bool {
		_, auto := flagValue([]string{a}, "auto-approve")
		return auto
	})...)
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

// plan runs a plan, shows it on out, and reads it back. Its code is plan
// -detailed-exitcode's: 0 for no changes, 2 for changes, 1 for errors.
func (r *batchRun) plan(hosts []string, out io.Writer) (*batchPlan, int) {
	r.runs++
	path := filepath.Join(r.tmp, fmt.Sprintf("plan-%d.tfplan", r.runs))
	code := r.run(r.planArgs(hosts, path), out)
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

// run runs conn3x with args and returns its exit code.
func (r *batchRun) run(args []string, out io.Writer) int {
	c := exec.Command(r.self, args...)
	c.Dir, c.Stdout, c.Stderr, c.Stdin = r.dir, out, r.errOut, r.in
	if out != r.out {
		c.Stderr = out // a batch's plan shows its errors only if it fails
	}
	// No "run conn3x apply" hints between batches.
	c.Env = append(os.Environ(), "TF_IN_AUTOMATION=1")
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
}

type batchChange struct {
	addr, module, typ, name string
	key                any
	actions            string
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
	}
	if err := json.Unmarshal(js, &raw); err != nil {
		return nil, err
	}
	p := &batchPlan{}
	for _, c := range raw.ResourceChanges {
		if c.Mode != "managed" {
			continue
		}
		p.changes = append(p.changes, batchChange{addr: c.Address, module: c.ModuleAddress, typ: c.Type, name: c.Name, key: c.Index, actions: strings.Join(c.Change.Actions, ",")})
	}
	return p, nil
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
