// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/modules/schedule"
	"github.com/opentofu/opentofu/internal/conn3x/modules/service"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// planSynced plans a resource whose computed in_sync says whether the host
// matches: replace when a key attribute or the host changes, update when any
// setting changed or refresh found the host out of sync. A host has only one
// of a resource with no keys, such as its hostname.
func planSynced(req providers.PlanResourceChangeRequest, kind string, keys, settings []string) providers.PlanResourceChangeResponse {
	var resp providers.PlanResourceChangeResponse
	if req.ProposedNewState.IsNull() {
		resp.PlannedState = req.ProposedNewState
		return resp
	}
	vals := req.ProposedNewState.AsValueMap()
	if v, ok := vals["on_remove"]; ok && v.IsNull() {
		vals["on_remove"] = cty.StringVal(defaultOnRemove)
	}
	host := req.ProposedNewState.GetAttr("ssh").GetAttr("host")
	vals["id"] = cty.UnknownVal(cty.String)
	if host.IsKnown() {
		id := []string{host.AsString(), kind}
		for _, k := range keys {
			if !vals[k].IsKnown() {
				id = nil
				break
			}
			id = append(id, stringOr(vals[k], ""))
		}
		if id != nil {
			vals["id"] = cty.StringVal(strings.Join(id, ":"))
		}
	}
	stale := req.PriorState.IsNull()
	if !stale {
		for _, k := range keys {
			if !req.PriorState.GetAttr(k).RawEquals(vals[k]) {
				resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath(k))
				stale = true
			}
		}
		if !req.PriorState.GetAttr("ssh").GetAttr("host").RawEquals(host) {
			resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath("ssh").GetAttr("host"))
			stale = true
		}
		for _, a := range settings {
			if !req.PriorState.GetAttr(a).RawEquals(vals[a]) {
				stale = true
			}
		}
		if s := req.PriorState.GetAttr("in_sync"); !known(s) || s.False() {
			stale = true
		}
	}
	vals["in_sync"] = cty.True
	if stale {
		vals["in_sync"] = cty.UnknownVal(cty.Bool)
	}
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

func withSync(v cty.Value, inSync bool) cty.Value {
	vals := v.AsValueMap()
	vals["in_sync"] = cty.BoolVal(inSync)
	return cty.ObjectVal(vals)
}

var cronSettings = []string{"schedule", "user", "command"}

func cronSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A job in /etc/cron.d.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"name":      {Type: cty.String, Required: true, Description: "File name in /etc/cron.d: letters, digits, - and _."},
			"schedule":  {Type: cty.String, Required: true, Description: "Five cron fields, or a macro such as @daily."},
			"user":      {Type: cty.String, Optional: true, Description: "User the job runs as. Defaults to root."},
			"command":   {Type: cty.String, Required: true, Description: "Command to run."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the job, \"delete\" removes it."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the job on the host matches."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func cronFrom(v cty.Value) schedule.Cron {
	return schedule.Cron{Name: v.GetAttr("name").AsString(), Schedule: v.GetAttr("schedule").AsString(),
		User: stringOr(v.GetAttr("user"), ""), Command: v.GetAttr("command").AsString()}
}

func validateCron(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := cronFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("schedule", err.Error()))
	}
	return diags
}

func planCron(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "cron", []string{"name"}, cronSettings)
}

func readCron(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		c := cronFrom(prior)
		want, err := c.Content()
		if err != nil {
			return cty.NilVal, err
		}
		a, err := file.Read(ctx, h, c.Path())
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, a.Exists && a.Content == want), nil
	})
}

func applyCron(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			c := cronFrom(planned)
			content, err := c.Content()
			if err != nil {
				return cty.NilVal, err
			}
			if res, err := h.Run(ctx, "test -d /etc/cron.d", nil); err != nil {
				return cty.NilVal, err
			} else if res.ExitCode != 0 {
				return cty.NilVal, fmt.Errorf("cron %s: /etc/cron.d does not exist, so no cron daemon is installed; add a package step for cronie (Red Hat family) or cron (Debian and Ubuntu) before this one", c.Name)
			}
			if err := file.Apply(ctx, h, file.Desired{Path: c.Path(), Content: content, Mode: "0644", Owner: "root", Group: "root"}); err != nil {
				return cty.NilVal, fmt.Errorf("cron %s: %w", c.Name, err)
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return file.Delete(ctx, h, cronFrom(prior).Path())
		})
}

var timerSettings = []string{"on_calendar", "user", "command", "description", "persistent"}

func timerSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A systemd timer that runs a command on a schedule.",
		Attributes: map[string]*configschema.Attribute{
			"id":          {Type: cty.String, Computed: true},
			"name":        {Type: cty.String, Required: true, Description: "Unit name, without .timer or .service."},
			"on_calendar": {Type: cty.String, Required: true, Description: "systemd calendar expression, such as \"daily\" or \"*-*-* 02:30:00\"."},
			"user":        {Type: cty.String, Optional: true, Description: "User the command runs as. Defaults to root."},
			"command":     {Type: cty.String, Required: true, Description: "Command to run (ExecStart)."},
			"description": {Type: cty.String, Optional: true, Description: "Unit description."},
			"persistent":  {Type: cty.Bool, Optional: true, Description: "Run a missed job at the next boot."},
			"on_remove":   {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the timer, \"delete\" stops it and removes its units."},
			"in_sync":     {Type: cty.Bool, Computed: true, Description: "Whether the units match and the timer is enabled and running."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func timerFrom(v cty.Value) schedule.Timer {
	p := v.GetAttr("persistent")
	return schedule.Timer{
		Name: v.GetAttr("name").AsString(), OnCalendar: v.GetAttr("on_calendar").AsString(),
		User: stringOr(v.GetAttr("user"), ""), Command: v.GetAttr("command").AsString(),
		Description: stringOr(v.GetAttr("description"), ""), Persistent: known(p) && p.True(),
	}
}

func validateTimer(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := timerFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("on_calendar", err.Error()))
	}
	return diags
}

func planTimer(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "timer", []string{"name"}, timerSettings)
}

func readTimer(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		t := timerFrom(prior)
		svc, tmr, err := t.Units()
		if err != nil {
			return cty.NilVal, err
		}
		svcPath, tmrPath := t.Paths()
		a, err := file.Read(ctx, h, svcPath)
		if err != nil {
			return cty.NilVal, err
		}
		b, err := file.Read(ctx, h, tmrPath)
		if err != nil {
			return cty.NilVal, err
		}
		unit, err := service.Read(ctx, h, t.Name+".timer")
		if err != nil {
			return cty.NilVal, err
		}
		ok := a.Content == svc && b.Content == tmr && unit.Exists && unit.Running && unit.Enabled && !unit.NeedsReload
		return withSync(prior, ok), nil
	})
}

func applyTimer(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			t := timerFrom(planned)
			svc, tmr, err := t.Units()
			if err != nil {
				return cty.NilVal, err
			}
			svcPath, tmrPath := t.Paths()
			for path, content := range map[string]string{svcPath: svc, tmrPath: tmr} {
				if err := file.Apply(ctx, h, file.Desired{Path: path, Content: content, Mode: "0644", Owner: "root", Group: "root"}); err != nil {
					return cty.NilVal, fmt.Errorf("timer %s: %w", t.Name, err)
				}
			}
			on := true
			if err := service.Apply(ctx, h, service.Desired{Name: t.Name + ".timer", State: service.Started, Enabled: &on}); err != nil {
				return cty.NilVal, fmt.Errorf("timer %s: %w", t.Name, err)
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			t := timerFrom(prior)
			off := false
			if err := service.Apply(ctx, h, service.Desired{Name: t.Name + ".timer", State: service.Stopped, Enabled: &off}); err != nil {
				return err
			}
			svcPath, tmrPath := t.Paths()
			for _, p := range []string{tmrPath, svcPath} {
				if err := file.Delete(ctx, h, p); err != nil {
					return err
				}
			}
			_, err := h.Run(ctx, "systemctl daemon-reload", nil)
			return err
		})
}
