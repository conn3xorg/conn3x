// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/schedule"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func crontabSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "The whole of one user's crontab, the one crontab -e edits: exactly these jobs and environment lines, and no other.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"user":      {Type: cty.String, Required: true, Description: "The user whose crontab this is. The jobs run as them."},
			"env":       {Type: cty.Map(cty.String), Optional: true, Description: "Environment lines at the top of the crontab, such as MAILTO or PATH."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the crontab as it is when the step is removed; \"delete\" removes the user's whole crontab."},
			"unlisted":  {Type: cty.List(cty.String), Computed: true, Description: "Lines in the crontab the step doesn't list, as of the last refresh: a job by its schedule and a hash of the line, never its command. Apply removes them."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the crontab was exactly this at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{
			"ssh": connectionBlock(),
			"job": {
				Nesting: configschema.NestingList,
				Block: configschema.Block{
					Description: "One job in the crontab.",
					Attributes: map[string]*configschema.Attribute{
						"name":     {Type: cty.String, Required: true, Description: "A name for the job, written in a comment above it: letters, digits, - and _."},
						"schedule": {Type: cty.String, Required: true, Description: "When it runs: five fields, such as \"0 3 * * *\", or a macro such as \"@daily\"."},
						"command":  {Type: cty.String, Required: true, Description: "The command, one line. A % in it is kept as a %."},
					},
				},
			},
		},
	}}
}

func crontabFrom(v cty.Value) schedule.Crontab {
	c := schedule.Crontab{User: stringOr(v.GetAttr("user"), "")}
	if env := v.GetAttr("env"); known(env) {
		c.Env = map[string]string{}
		for k, e := range env.AsValueMap() {
			c.Env[k] = stringOr(e, "")
		}
	}
	if jobs := v.GetAttr("job"); known(jobs) {
		for _, j := range jobs.AsValueSlice() {
			c.Jobs = append(c.Jobs, schedule.Job{Name: stringOr(j.GetAttr("name"), ""), Schedule: stringOr(j.GetAttr("schedule"), ""), Command: stringOr(j.GetAttr("command"), "")})
		}
	}
	return c
}

func validateCrontab(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := crontabFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("job", err.Error()))
	}
	return diags
}

func planCrontab(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	resp := planSynced(req, "crontab", []string{"user"}, []string{"env", "job"})
	if resp.PlannedState.IsNull() {
		return resp
	}
	vals := resp.PlannedState.AsValueMap()
	vals["unlisted"] = cty.ListValEmpty(cty.String)
	if !req.PriorState.IsNull() {
		if u := req.PriorState.GetAttr("unlisted"); !known(u) || u.LengthInt() > 0 {
			vals["in_sync"] = cty.UnknownVal(cty.Bool)
		}
	}
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

func crontabUnlisted(gone []schedule.Unlisted) cty.Value {
	if len(gone) == 0 {
		return cty.ListValEmpty(cty.String)
	}
	vals := make([]cty.Value, len(gone))
	for i, g := range gone {
		vals[i] = cty.StringVal(g.String())
	}
	return cty.ListVal(vals)
}

func readCrontab(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	var gone []schedule.Unlisted
	resp := readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		c := crontabFrom(prior)
		current, err := schedule.ReadCrontab(ctx, h, c.User)
		if err != nil {
			return cty.NilVal, err
		}
		var want string
		want, gone = c.Want(current)
		vals := prior.AsValueMap()
		vals["in_sync"] = cty.BoolVal(want == current)
		vals["unlisted"] = crontabUnlisted(gone)
		return cty.ObjectVal(vals), nil
	})
	if len(gone) > 0 && !resp.Diagnostics.HasErrors() {
		// The schedule and the command's first word are enough to know the
		// job by, without an argument that might be a secret.
		var names []string
		for _, g := range gone {
			switch g.Kind {
			case "job":
				names = append(names, g.Schedule+" "+g.Head+" …")
			case "env":
				names = append(names, g.Schedule+"=…")
			default:
				names = append(names, "a line that isn't a job ("+g.Hash+")")
			}
		}
		user := req.PriorState.GetAttr("user").AsString()
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(fmt.Sprintf(
			"%s's crontab has %d line(s) the crontab step doesn't list, which apply removes: %s", user, len(gone), strings.Join(names, "; "))))
	}
	return resp
}

func applyCrontab(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			c := crontabFrom(planned)
			if err := c.Validate(); err != nil {
				return cty.NilVal, err
			}
			current, err := schedule.ReadCrontab(ctx, h, c.User)
			if err != nil {
				return cty.NilVal, err
			}
			if want, _ := c.Want(current); want != current {
				if err := schedule.WriteCrontab(ctx, h, c.User, want); err != nil {
					return cty.NilVal, err
				}
			}
			vals := planned.AsValueMap()
			vals["in_sync"] = cty.True
			vals["unlisted"] = cty.ListValEmpty(cty.String)
			return cty.ObjectVal(vals), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return schedule.RemoveCrontab(ctx, h, prior.GetAttr("user").AsString())
		})
}
