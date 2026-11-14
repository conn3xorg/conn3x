// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"

	"github.com/opentofu/opentofu/internal/conn3x/convert/ansible"
	"github.com/opentofu/opentofu/internal/conn3x/hostpattern"
	"github.com/opentofu/opentofu/internal/conn3x/termsafe"
)

// taskPlan is a plan file: task runs in order, each on its own hosts, as a
// Bolt plan runs tasks.
type taskPlan struct {
	name   string
	params map[string]*cty.Value // nil: required
	runs   []planRun
}

type planRun struct {
	name          string
	task          *runTask
	hosts, params hcl.Expression // params may be nil
}

var planFileSchema = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "plan", LabelNames: []string{"name"}}}}

var planSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "description"}},
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "param", LabelNames: []string{"name"}},
		{Type: "run", LabelNames: []string{"name"}},
	},
}

var planRunSchema = &hcl.BodySchema{Attributes: []hcl.AttributeSchema{
	{Name: "task", Required: true},
	{Name: "hosts", Required: true},
	{Name: "params"},
}}

// loadPlan reads the one plan in path, and the task files its runs name,
// relative to it.
func loadPlan(path string) (*taskPlan, error) {
	f, diags := hclparse.NewParser().ParseHCLFile(path)
	if diags.HasErrors() {
		return nil, diags
	}
	content, diags := f.Body.Content(planFileSchema)
	if diags.HasErrors() {
		return nil, diags
	}
	if len(content.Blocks) != 1 {
		return nil, fmt.Errorf("%s must hold one plan block, not %d", path, len(content.Blocks))
	}
	pb := content.Blocks[0]
	p := &taskPlan{name: pb.Labels[0], params: map[string]*cty.Value{}}
	body, diags := pb.Body.Content(planSchema)
	if diags.HasErrors() {
		return nil, diags
	}
	seen := map[string]bool{}
	var err error
	for _, b := range body.Blocks {
		name := b.Labels[0]
		if b.Type == "param" {
			if p.params[name], err = paramDefault(b); err != nil {
				return nil, err
			}
			continue
		}
		if seen[name] {
			return nil, fmt.Errorf("plan %s has two runs named %s", p.name, name)
		}
		seen[name] = true
		rc, diags := b.Body.Content(planRunSchema)
		if diags.HasErrors() {
			return nil, diags
		}
		file, diags := rc.Attributes["task"].Expr.Value(nil)
		if diags.HasErrors() || file.Type() != cty.String || file.IsNull() {
			return nil, fmt.Errorf("run %s: task must be the task file's path, as a string", name)
		}
		taskPath := file.AsString()
		if !filepath.IsAbs(taskPath) {
			taskPath = filepath.Join(filepath.Dir(path), taskPath)
		}
		t, err := loadTask(taskPath)
		if err != nil {
			return nil, fmt.Errorf("run %s: %w", name, err)
		}
		r := planRun{name: name, task: t, hosts: rc.Attributes["hosts"].Expr}
		if a, ok := rc.Attributes["params"]; ok {
			r.params = a.Expr
		}
		p.runs = append(p.runs, r)
	}
	if len(p.runs) == 0 {
		return nil, fmt.Errorf("plan %s has no runs", p.name)
	}
	return p, nil
}

// planStep is one run, ready: its hosts and its task's params.
type planStep struct {
	run    planRun
	hosts  []*runHost
	params cty.Value
}

// runPlanOn works out every run's hosts and params first, so a mistake in
// a later run stops the plan before anything runs, then runs them in order
// and stops at the first run where a host failed.
func (o runOptions) runPlanOn(ctx context.Context, plan *taskPlan, params cty.Value, inv *ansible.Inventory, hostsFor func(*hostpattern.Pattern) []*runHost, stdout, stderr io.Writer) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintln(stderr, termsafe.Escape(fmt.Sprintf("Error: "+format, a...)))
		return 1
	}
	ectx := &hcl.EvalContext{Variables: map[string]cty.Value{"param": params}}
	var steps []planStep
	for _, r := range plan.runs {
		hv, diags := r.hosts.Value(ectx)
		if diags.HasErrors() {
			return fail("run %s: hosts: %s", r.name, diags.Error())
		}
		hv, err := convert.Convert(hv, cty.String)
		if err != nil || hv.IsNull() || !hv.IsKnown() {
			return fail("run %s: hosts must be a host pattern, as a string", r.name)
		}
		pat, err := hostpattern.Parse(hv.AsString())
		if err != nil {
			return fail("run %s: %s", r.name, err)
		}
		pat.Resolve(func(g string) []string {
			if inv.Group(g) == nil {
				return nil
			}
			return inv.Ordered(g)
		})
		given := map[string]cty.Value{}
		if r.params != nil {
			pv, diags := r.params.Value(ectx)
			if diags.HasErrors() {
				return fail("run %s: params: %s", r.name, diags.Error())
			}
			if pv.IsNull() || !(pv.Type().IsObjectType() || pv.Type().IsMapType()) {
				return fail("run %s: params must be an object, such as { version = param.version }", r.name)
			}
			given = pv.AsValueMap()
		}
		tp, err := paramValues("run "+r.name+": task "+r.task.name, r.task.params, given)
		if err != nil {
			return fail("%s", err)
		}
		steps = append(steps, planStep{run: r, hosts: hostsFor(pat), params: tp})
	}

	for i, s := range steps {
		if !o.json {
			fmt.Fprintln(stdout, termsafe.Escape(fmt.Sprintf("== %s: task %s, %d host(s)", s.run.name, s.run.task.name, len(s.hosts))))
		}
		o.runOn(ctx, s.hosts, s.run.task, s.params, "", nil)
		if o.report(stdout, s.run.name, s.hosts, true) == 0 {
			continue
		}
		for _, rest := range steps[i+1:] {
			if o.json {
				line, _ := json.Marshal(map[string]any{"run": rest.run.name, "status": "skipped"})
				fmt.Fprintln(stdout, string(line))
				continue
			}
			fmt.Fprintln(stdout, termsafe.Escape(fmt.Sprintf("== %s: skipped, since %s failed", rest.run.name, s.run.name)))
		}
		return 2
	}
	return 0
}
