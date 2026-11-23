// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/supervisor"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func supervisorSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A supervisord program or group: whether it's loaded, and whether it runs, kept with supervisorctl.",
		Attributes: map[string]*configschema.Attribute{
			"id":                 {Type: cty.String, Computed: true},
			"revision":           revisionAttr(),
			"name":               {Type: cty.String, Required: true, Description: "The program, such as \"app\", or a group with a trailing colon, such as \"web:\", as supervisorctl takes it."},
			"state":              {Type: cty.String, Required: true, Description: "\"started\", \"stopped\", \"present\" (loaded, left running or stopped as it is) or \"absent\" (stopped and removed from supervisord)."},
			"config":             {Type: cty.String, Optional: true, Description: "supervisorctl's configuration file, absolute, passed as -c. When supervisord asks for a login, put username and password in its [supervisorctl] section."},
			"server_url":         {Type: cty.String, Optional: true, Description: "Where supervisord listens, such as \"http://127.0.0.1:9001\", passed as -s. It can't hold a login."},
			"supervisorctl_path": {Type: cty.String, Optional: true, Description: "supervisorctl, absolute. Found on PATH when unset."},
			"triggers":           {Type: cty.DynamicPseudoType, Optional: true, Description: "Any value, such as the revision of the step that writes the program's file; whenever it changes, the step runs supervisorctl update for the program, which rereads its file, and restarts it when its state is started."},
			"on_remove":          {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the program, \"delete\" stops it and removes it from supervisord."},
			"processes":          {Type: cty.Map(cty.String), Computed: true, Description: "Each process supervisorctl status listed at the last refresh, with its state, such as { app = \"RUNNING\" }."},
			"in_sync":            {Type: cty.Bool, Computed: true, Description: "Whether the program was in its state at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func supervisorFrom(v cty.Value) supervisor.Program {
	return supervisor.Program{
		Name:  stringOr(v.GetAttr("name"), ""),
		State: supervisor.State(stringOr(v.GetAttr("state"), "")),
		Conn: supervisor.Conn{
			Config:    stringOr(v.GetAttr("config"), ""),
			ServerURL: stringOr(v.GetAttr("server_url"), ""),
			Path:      stringOr(v.GetAttr("supervisorctl_path"), ""),
		},
	}
}

func validateSupervisor(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := supervisorFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planSupervisor(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	resp := planSynced(req, "supervisor_program", []string{"name"}, []string{"state", "triggers"})
	if p := resp.PlannedState; !p.IsNull() && !p.GetAttr("in_sync").IsKnown() {
		vals := p.AsValueMap()
		vals["processes"] = cty.UnknownVal(cty.Map(cty.String))
		resp.PlannedState = cty.ObjectVal(vals)
	}
	return resp
}

// supervisorState is v with what Read found.
func supervisorState(v cty.Value, procs []supervisor.Process) cty.Value {
	m := map[string]cty.Value{}
	for _, p := range procs {
		m[p.Name] = cty.StringVal(p.State)
	}
	vals := v.AsValueMap()
	vals["processes"] = cty.MapValEmpty(cty.String)
	if len(m) > 0 {
		vals["processes"] = cty.MapVal(m)
	}
	vals["in_sync"] = cty.BoolVal(supervisor.InSync(supervisor.State(stringOr(v.GetAttr("state"), "")), procs))
	return cty.ObjectVal(vals)
}

func readSupervisor(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		procs, err := supervisor.Read(ctx, h, supervisorFrom(prior))
		if err != nil {
			return cty.NilVal, err
		}
		return supervisorState(prior, procs), nil
	})
}

func applySupervisor(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			p := supervisorFrom(planned)
			t := planned.GetAttr("triggers")
			update := !t.IsNull() && (req.PriorState.IsNull() || !req.PriorState.GetAttr("triggers").RawEquals(t))
			if err := supervisor.Apply(ctx, h, p, update); err != nil {
				return cty.NilVal, fmt.Errorf("supervisor_program %s: %w", p.Name, err)
			}
			procs, err := supervisor.Read(ctx, h, p)
			if err != nil {
				return cty.NilVal, err
			}
			state := supervisorState(planned, procs)
			if state.GetAttr("in_sync").False() {
				return cty.NilVal, fmt.Errorf("supervisor_program %s did not reach state %q; check `supervisorctl status %s` and the program's log on the host", p.Name, p.State, p.Name)
			}
			return state, nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			p := supervisorFrom(prior)
			p.State = supervisor.Absent
			if err := supervisor.Apply(ctx, h, p, false); err != nil {
				return fmt.Errorf("supervisor_program %s: %w", p.Name, err)
			}
			return nil
		})
}
