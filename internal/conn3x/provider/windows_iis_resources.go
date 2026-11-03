// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

var iisStateAttr = &configschema.Attribute{Type: cty.String, Optional: true, Description: "\"started\" (default) or \"stopped\". Also whether it starts with IIS."}

func winAppPoolSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. An IIS application pool, found by its name.",
		Attributes: map[string]*configschema.Attribute{
			"id":                      {Type: cty.String, Computed: true},
			"revision":                revisionAttr(),
			"name":                    {Type: cty.String, Required: true, Description: "The pool's name: letters, digits, spaces and . _ ( ) -."},
			"state":                   iisStateAttr,
			"managed_runtime_version": {Type: cty.String, Optional: true, Description: "\"v4.0\" (default), \"v2.0\", or \"\" for no managed code."},
			"pipeline_mode":           {Type: cty.String, Optional: true, Description: "\"integrated\" (default) or \"classic\"."},
			"identity":                {Type: cty.String, Optional: true, Description: "Account the pool runs as: \"ApplicationPoolIdentity\" (default), \"NetworkService\", \"LocalService\" or \"LocalSystem\"."},
			"on_remove":               {Type: cty.String, Optional: true, Computed: true, Description: "\"delete\" (default) deletes the pool when the step is removed or replaced, \"forget\" leaves it."},
			"in_sync":                 {Type: cty.Bool, Computed: true, Description: "Whether the pool matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winAppPoolFrom(v cty.Value) windows.AppPool {
	return windows.AppPool{
		Name: stringOr(v.GetAttr("name"), ""), Started: stringOr(v.GetAttr("state"), "started") == "started",
		RuntimeVersion: stringOr(v.GetAttr("managed_runtime_version"), "v4.0"), PipelineMode: stringOr(v.GetAttr("pipeline_mode"), "integrated"),
		Identity: stringOr(v.GetAttr("identity"), "ApplicationPoolIdentity"),
	}
}

func validateIISState(cfg cty.Value) tfdiags.Diagnostics {
	if s := cfg.GetAttr("state"); known(s) && s.AsString() != "started" && s.AsString() != "stopped" {
		return tfdiags.Diagnostics{}.Append(attrError("state", fmt.Sprintf(`state %q must be "started" or "stopped"`, s.AsString())))
	}
	return nil
}

func validateWinAppPool(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg), validateIISState(cfg))
	for _, a := range append([]string{"name"}, winAppPoolSettings...) {
		if !cfg.GetAttr(a).IsWhollyKnown() {
			return diags
		}
	}
	if err := winAppPoolFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

var winAppPoolSettings = []string{"state", "managed_runtime_version", "pipeline_mode", "identity"}

func planWinAppPool(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSyncedFold(deleteByDefault(req), "windows_iis_app_pool", []string{"name"}, winAppPoolSettings)
}

func readWinAppPool(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	p := winAppPoolFrom(req.PriorState)
	a, err := windows.ReadAppPool(ctx, h.client, p.Name)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(req.PriorState, p.Matches(a))
	return resp
}

func applyWinAppPool(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_iis_app_pool: %w", err))
		return resp
	}
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState
		if req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
		if err != nil {
			return fail(err)
		}
		if err := windows.ApplyAppPoolRemove(ctx, h.client, stringOr(req.PriorState.GetAttr("name"), "")); err != nil {
			return fail(err)
		}
		return resp
	}
	p := winAppPoolFrom(req.PlannedState)
	if err := p.Validate(); err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	a, err := windows.ReadAppPool(ctx, h.client, p.Name)
	if err != nil {
		return fail(err)
	}
	if !p.Matches(a) {
		if err := windows.ApplyAppPool(ctx, h.client, p); err != nil {
			return fail(fmt.Errorf("pool %s: %w", p.Name, err))
		}
		if a, err = windows.ReadAppPool(ctx, h.client, p.Name); err != nil {
			return fail(err)
		}
		if !p.Matches(a) {
			return fail(fmt.Errorf("pool %s doesn't match what was set: %+v", p.Name, a))
		}
	}
	resp.NewState = withSync(req.PlannedState, true)
	return resp
}

func winSiteSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. An IIS site, found by its name.",
		Attributes: map[string]*configschema.Attribute{
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"name":          {Type: cty.String, Required: true, Description: "The site's name: letters, digits, spaces and . _ ( ) -."},
			"physical_path": {Type: cty.String, Required: true, Description: "Folder the site serves, on a local drive, such as C:\\sites\\www."},
			"app_pool":      {Type: cty.String, Optional: true, Description: "Application pool the site runs in, which must exist. A new site gets IIS's default; an existing one keeps its own when unset."},
			"state":         iisStateAttr,
			"on_remove":     {Type: cty.String, Optional: true, Computed: true, Description: "\"delete\" (default) deletes the site when the step is removed or replaced, \"forget\" leaves it. Its files stay either way."},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the site matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{
			"ssh": connectionBlock(),
			"binding": {
				Nesting:  configschema.NestingList,
				MinItems: 1,
				Block: configschema.Block{
					Description: "Where the site listens. These are all its bindings: one added by hand shows as drift and is removed.",
					Attributes: map[string]*configschema.Attribute{
						"protocol":    {Type: cty.String, Optional: true, Description: "\"http\" (default), the only one for now."},
						"ip":          {Type: cty.String, Optional: true, Description: "Address to listen on, or \"*\" (default) for all."},
						"port":        {Type: cty.Number, Required: true, Description: "Port, such as 80."},
						"host_header": {Type: cty.String, Optional: true, Description: "Host name the site answers to, such as www.example.com. Unset answers any."},
					},
				},
			},
		},
	}}
}

func winSiteFrom(v cty.Value) windows.Site {
	s := windows.Site{
		Name: stringOr(v.GetAttr("name"), ""), PhysicalPath: stringOr(v.GetAttr("physical_path"), ""), AppPool: stringOr(v.GetAttr("app_pool"), ""),
		Started: stringOr(v.GetAttr("state"), "started") == "started",
	}
	if bs := v.GetAttr("binding"); known(bs) {
		for it := bs.ElementIterator(); it.Next(); {
			_, e := it.Element()
			b := windows.Binding{Protocol: stringOr(e.GetAttr("protocol"), "http"), IP: stringOr(e.GetAttr("ip"), "*"), HostHeader: stringOr(e.GetAttr("host_header"), "")}
			if p := e.GetAttr("port"); known(p) {
				n, _ := p.AsBigFloat().Int64()
				b.Port = int(n)
			}
			s.Bindings = append(s.Bindings, b)
		}
	}
	return s
}

var winSiteSettings = []string{"physical_path", "app_pool", "state", "binding"}

func validateWinSite(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg), validateIISState(cfg))
	for _, a := range append([]string{"name"}, winSiteSettings...) {
		if !cfg.GetAttr(a).IsWhollyKnown() {
			return diags
		}
	}
	if err := winSiteFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planWinSite(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSyncedFold(deleteByDefault(req), "windows_iis_site", []string{"name"}, winSiteSettings)
}

func readWinSite(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	s := winSiteFrom(req.PriorState)
	a, err := windows.ReadSite(ctx, h.client, s.Name)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(req.PriorState, s.Matches(a))
	return resp
}

func applyWinSite(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_iis_site: %w", err))
		return resp
	}
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState
		if req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
		if err != nil {
			return fail(err)
		}
		if err := windows.ApplySiteRemove(ctx, h.client, stringOr(req.PriorState.GetAttr("name"), "")); err != nil {
			return fail(err)
		}
		return resp
	}
	s := winSiteFrom(req.PlannedState)
	if err := s.Validate(); err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	a, err := windows.ReadSite(ctx, h.client, s.Name)
	if err != nil {
		return fail(err)
	}
	if !s.Matches(a) {
		if err := windows.ApplySite(ctx, h.client, s); err != nil {
			return fail(fmt.Errorf("site %s: %w", s.Name, err))
		}
		if a, err = windows.ReadSite(ctx, h.client, s.Name); err != nil {
			return fail(err)
		}
		if !s.Matches(a) {
			return fail(fmt.Errorf("site %s doesn't match what was set: %+v", s.Name, a))
		}
	}
	resp.NewState = withSync(req.PlannedState, true)
	return resp
}
