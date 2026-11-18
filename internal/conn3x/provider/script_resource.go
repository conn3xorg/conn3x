// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/script"
	"github.com/opentofu/opentofu/internal/providers"
)

func scriptSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. A module you wrote yourself: a program in the circuit's directory, in any language the host runs, that reads and changes the host and speaks JSON on stdin and stdout. Conn3x copies it to the host and keeps the plan, state and drift.",
		Attributes: map[string]*configschema.Attribute{
			"id":             {Type: cty.String, Computed: true},
			"revision":       revisionAttr(),
			"program":        {Type: cty.String, Required: true, Description: "The program's contents. A script step sets it from source with file()."},
			"program_sha256": {Type: cty.String, Computed: true, Description: "The program's SHA-256, so editing it shows as a change."},
			"interpreter":    {Type: cty.List(cty.String), Optional: true, Description: "Runs the program with these first, such as [\"python3\"]. Unset runs it directly, by its #! line."},
			"args":           {Type: cty.String, Optional: true, Description: "The arguments, as JSON. A script step sets it from args with jsonencode()."},
			"args_wo":        {Type: cty.String, Optional: true, WriteOnly: true, Description: "Arguments kept out of plan and state, as JSON, such as a password. The program gets them in apply only."},
			"state":          {Type: cty.String, Computed: true, Description: "What the program's read returned, as JSON."},
			"changes":        {Type: cty.String, Computed: true, Description: "What the program's plan said would change, as JSON."},
			"on_remove":      {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the host as it is when the step is removed; \"delete\" runs the program's remove."},
			"in_sync":        {Type: cty.Bool, Computed: true, Description: "Whether the program's plan found nothing to change."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func scriptFrom(v cty.Value) script.Script {
	s := script.Script{Program: []byte(v.GetAttr("program").AsString())}
	if a := v.GetAttr("args"); !a.IsNull() && a.IsKnown() {
		s.Args = json.RawMessage(a.AsString())
	}
	if a := v.GetAttr("args_wo"); !a.IsNull() && a.IsKnown() {
		s.ArgsWO = json.RawMessage(a.AsString())
	}
	if l := v.GetAttr("interpreter"); !l.IsNull() && l.IsKnown() {
		for _, e := range l.AsValueSlice() {
			s.Interpreter = append(s.Interpreter, e.AsString())
		}
	}
	return s
}

func validateScript(v cty.Value) error {
	if p := v.GetAttr("program"); p.IsNull() || !p.IsKnown() {
		return nil
	}
	return scriptFrom(v).Validate()
}

func planScript(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	resp := planSynced(req, "script", nil, []string{"program", "interpreter", "args"})
	if resp.PlannedState.IsNull() {
		return resp
	}
	vals := resp.PlannedState.AsValueMap()
	if p := vals["program"]; p.IsKnown() && !p.IsNull() {
		vals["program_sha256"] = cty.StringVal(scriptFrom(resp.PlannedState).Sum())
	} else {
		vals["program_sha256"] = cty.UnknownVal(cty.String)
	}
	if s := vals["in_sync"]; !s.IsKnown() {
		vals["state"] = cty.UnknownVal(cty.String)
		vals["changes"] = cty.UnknownVal(cty.String)
	}
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

// readScript runs the program's read, then its plan against the result,
// so the plan shows what it would change and drift shows as out of sync.
func readScript(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		s := scriptFrom(prior)
		got, err := s.Call(ctx, h, "read", stateOf(prior))
		if err != nil {
			return cty.NilVal, err
		}
		plan, err := s.Call(ctx, h, "plan", got.State)
		if err != nil {
			return cty.NilVal, err
		}
		vals := prior.AsValueMap()
		vals["state"] = cty.StringVal(string(orNull(got.State)))
		vals["changes"] = cty.StringVal(string(orEmptyList(plan.Changes)))
		vals["in_sync"] = cty.BoolVal(*plan.InSync)
		return cty.ObjectVal(vals), nil
	})
}

func applyScript(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			// The write-only arguments are in the config, not the plan.
			s := scriptFrom(planned)
			if !req.Config.IsNull() {
				if a := req.Config.GetAttr("args_wo"); !a.IsNull() && a.IsKnown() {
					s.ArgsWO = json.RawMessage(a.AsString())
				}
			}
			var prior json.RawMessage
			if !req.PriorState.IsNull() {
				prior = stateOf(req.PriorState)
			}
			got, err := s.Call(ctx, h, "apply", prior)
			if err != nil {
				return cty.NilVal, fmt.Errorf("script: %w", err)
			}
			vals := planned.AsValueMap()
			vals["args_wo"] = cty.NullVal(cty.String)
			vals["state"] = cty.StringVal(string(orNull(got.State)))
			vals["changes"] = cty.StringVal("[]")
			vals["in_sync"] = cty.True
			return cty.ObjectVal(vals), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			_, err := scriptFrom(prior).Call(ctx, h, "remove", stateOf(prior))
			return err
		})
}

func stateOf(v cty.Value) json.RawMessage {
	if s := v.GetAttr("state"); !s.IsNull() && s.IsKnown() && s.AsString() != "" {
		return json.RawMessage(s.AsString())
	}
	return nil
}

func orNull(m json.RawMessage) json.RawMessage {
	if len(m) == 0 {
		return json.RawMessage("null")
	}
	return m
}

func orEmptyList(m json.RawMessage) json.RawMessage {
	if len(m) == 0 {
		return json.RawMessage("[]")
	}
	return m
}
