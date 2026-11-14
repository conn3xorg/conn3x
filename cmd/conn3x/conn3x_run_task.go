// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hcldec"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"

	"github.com/opentofu/opentofu/internal/configs"
	"github.com/opentofu/opentofu/internal/conn3x/convert/ansible"
	"github.com/opentofu/opentofu/internal/conn3x/provider"
)

// runTask is a task file: steps run in order on each host, without state,
// as Bolt runs a task. Its steps are the same module blocks a circuit's
// steps hold.
type runTask struct {
	name   string
	params map[string]*cty.Value // nil: required
	steps  []taskStep
}

type taskStep struct {
	name, module, typ string
	body              hcl.Body
}

var taskFileSchema = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "task", LabelNames: []string{"name"}}}}

var taskSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "description"}},
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "param", LabelNames: []string{"name"}},
		{Type: "step", LabelNames: []string{"name"}},
	},
}

// loadTask reads the one task in path.
func loadTask(path string) (*runTask, error) {
	f, diags := hclparse.NewParser().ParseHCLFile(path)
	if diags.HasErrors() {
		return nil, diags
	}
	content, diags := f.Body.Content(taskFileSchema)
	if diags.HasErrors() {
		return nil, diags
	}
	if len(content.Blocks) != 1 {
		return nil, fmt.Errorf("%s must hold one task block, not %d", path, len(content.Blocks))
	}
	tb := content.Blocks[0]
	t := &runTask{name: tb.Labels[0], params: map[string]*cty.Value{}}
	body, diags := tb.Body.Content(taskSchema)
	if diags.HasErrors() {
		return nil, diags
	}
	modules := configs.Conn3xStepModules()
	seen := map[string]bool{}
	var err error
	for _, b := range body.Blocks {
		name := b.Labels[0]
		switch b.Type {
		case "param":
			if t.params[name], err = paramDefault(b); err != nil {
				return nil, err
			}
		case "step":
			if seen[name] {
				return nil, fmt.Errorf("task %s has two steps named %s", t.name, name)
			}
			seen[name] = true
			blocks, diags := stepModuleBlock(b.Body)
			if diags.HasErrors() {
				return nil, diags
			}
			mod := blocks.Type
			typ, ok := modules[mod]
			if !ok {
				return nil, fmt.Errorf("step %s: %q isn't a module a task can run", name, mod)
			}
			// Junos and VyOS steps outside a circuit commit on their own.
			// EOS steps wait for a circuit's commit, which a task hasn't got.
			if strings.HasPrefix(typ, "conn3x_eos_") {
				return nil, fmt.Errorf("step %s: %q only runs in a circuit, which commits a switch's EOS steps together", name, mod)
			}
			t.steps = append(t.steps, taskStep{name: name, module: mod, typ: typ, body: blocks.Body})
		}
	}
	if len(t.steps) == 0 {
		return nil, fmt.Errorf("task %s has no steps", t.name)
	}
	return t, nil
}

// paramDefault is a param block's default, nil when it has none.
func paramDefault(b *hcl.Block) (*cty.Value, error) {
	attrs, diags := b.Body.JustAttributes()
	if diags.HasErrors() {
		return nil, diags
	}
	d, ok := attrs["default"]
	if !ok {
		return nil, nil
	}
	v, diags := d.Expr.Value(nil)
	if diags.HasErrors() {
		return nil, diags
	}
	return &v, nil
}

// stepModuleBlock is a step's one module block, whatever its type.
func stepModuleBlock(body hcl.Body) (*hcl.Block, hcl.Diagnostics) {
	var schema hcl.BodySchema
	for name := range configs.Conn3xStepModules() {
		schema.Blocks = append(schema.Blocks, hcl.BlockHeaderSchema{Type: name})
	}
	content, diags := body.Content(&schema)
	if diags.HasErrors() {
		return nil, diags
	}
	if len(content.Blocks) != 1 {
		return nil, hcl.Diagnostics{{Severity: hcl.DiagError, Summary: "A task step holds one module block", Detail: fmt.Sprintf("This step has %d.", len(content.Blocks)), Subject: body.MissingItemRange().Ptr()}}
	}
	return content.Blocks[0], nil
}

// paramValues are a task's or a plan's params, from what was given, with
// defaults for the rest. what names it in errors, as in "task deploy".
func paramValues(what string, declared map[string]*cty.Value, given map[string]cty.Value) (cty.Value, error) {
	vals := map[string]cty.Value{}
	for name, def := range declared {
		switch v, ok := given[name]; {
		case ok:
			vals[name] = v
		case def != nil:
			vals[name] = *def
		default:
			return cty.NilVal, fmt.Errorf("%s needs param %s: give it with -a '%s=...'", what, name, name)
		}
	}
	for name := range given {
		if _, ok := declared[name]; !ok {
			return cty.NilVal, fmt.Errorf("%s has no param %q", what, name)
		}
	}
	return cty.ObjectVal(vals), nil
}

// args evaluates a step's module block for one host, nested blocks
// included, as a circuit would decode it.
func (s taskStep) args(ctx context.Context, params, host cty.Value) (map[string]cty.Value, error) {
	p, _ := provider.New()
	block := p.GetProviderSchema(ctx).ResourceTypes[s.typ].Block
	ectx := &hcl.EvalContext{
		Variables: map[string]cty.Value{"param": params, "host": host},
		Functions: map[string]function.Function{"upper": stdlib.UpperFunc, "lower": stdlib.LowerFunc, "join": stdlib.JoinFunc, "format": stdlib.FormatFunc},
	}
	// The ssh block comes from the inventory and flags, so a step can't set one.
	noSSH := *block
	noSSH.BlockTypes = maps.Clone(block.BlockTypes)
	delete(noSSH.BlockTypes, "ssh")
	val, diags := hcldec.Decode(s.body, noSSH.DecoderSpec(), ectx)
	if diags.HasErrors() {
		return nil, fmt.Errorf("step %s: %s", s.name, diags.Error())
	}
	out := map[string]cty.Value{}
	for name, v := range val.AsValueMap() {
		if v.IsNull() {
			continue
		}
		attr := block.Attributes[name]
		if attr != nil && ((attr.Computed && !attr.Optional) || slices.Contains([]string{"id", "revision", "in_sync", "on_remove"}, name)) {
			return nil, fmt.Errorf("step %s: %s has no argument %q", s.name, s.module, name)
		}
		out[name] = v
	}
	return out, nil
}

// taskResult is one step's outcome on one host.
type taskResult struct {
	Step   string `json:"step"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	Stdout string `json:"stdout,omitempty"`
	Stderr string `json:"stderr,omitempty"`
}

// runTaskOn runs every step on one host in order, stopping at the first
// that fails, and returns the host's status: failed, changed or ok.
func runTaskOn(ctx context.Context, t *runTask, params cty.Value, name string, vars map[string]string, ssh map[string]cty.Value, check bool) (string, []taskResult) {
	hv := cty.MapValEmpty(cty.String)
	if m := map[string]cty.Value{}; len(vars) > 0 {
		for k, v := range vars {
			if !ansible.Encrypted(v) {
				m[k] = cty.StringVal(v)
			}
		}
		if len(m) > 0 {
			hv = cty.MapVal(m)
		}
	}
	host := cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal(name), "vars": hv})
	status := "ok"
	var results []taskResult
	for _, s := range t.steps {
		args, err := s.args(ctx, params, host)
		if err == nil {
			var res provider.RunResult
			res, err = provider.RunOnce(ctx, s.typ, args, ssh, check)
			r := taskResult{Step: s.name, Status: "ok", Stdout: res.Stdout, Stderr: res.Stderr}
			switch {
			case err != nil:
			case res.Changed && check:
				r.Status, status = "would change", "would change"
			case res.Changed:
				r.Status, status = "changed", "changed"
			}
			if err == nil {
				results = append(results, r)
				continue
			}
		}
		results = append(results, taskResult{Step: s.name, Status: "failed", Error: err.Error()})
		return "failed", results
	}
	return status, results
}
