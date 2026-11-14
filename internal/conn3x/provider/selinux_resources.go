// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/selinux"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func selinuxBooleanSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "An SELinux boolean, set now and across reboots. Removing it leaves the value as it is.",
		Attributes: map[string]*configschema.Attribute{
			"id":       {Type: cty.String, Computed: true},
			"revision": revisionAttr(),
			"name":     {Type: cty.String, Required: true, Description: "Boolean, such as httpd_can_network_connect."},
			"value":    {Type: cty.Bool, Required: true, Description: "Whether it is on."},
			"in_sync":  {Type: cty.Bool, Computed: true, Description: "Whether the running value matches."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateSELinuxBoolean(cfg cty.Value) tfdiags.Diagnostics {
	return validateName(cfg, selinux.ValidateBoolean)
}

func planSELinuxBoolean(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "selinux_boolean", []string{"name"}, []string{"value"})
}

func readSELinuxBoolean(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		on, err := selinux.ReadBoolean(ctx, h, prior.GetAttr("name").AsString())
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, on == prior.GetAttr("value").True()), nil
	})
}

func applySELinuxBoolean(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			name := planned.GetAttr("name").AsString()
			if err := selinux.ApplyBoolean(ctx, h, name, planned.GetAttr("value").True()); err != nil {
				return cty.NilVal, fmt.Errorf("selinux_boolean %s: %w", name, err)
			}
			return withSync(planned, true), nil
		}, nil)
}

func selinuxFcontextSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A local SELinux file context rule. Conn3x relabels the files it covers after every change.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"target":    {Type: cty.String, Required: true, Description: "Path expression, such as /srv/www(/.*)?."},
			"setype":    {Type: cty.String, Required: true, Description: "SELinux type, such as httpd_sys_content_t."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) keeps the rule, \"delete\" removes it and relabels."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the host has the rule."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func fcontextFrom(v cty.Value) selinux.Fcontext {
	return selinux.Fcontext{Target: v.GetAttr("target").AsString(), Type: v.GetAttr("setype").AsString()}
}

func validateSELinuxFcontext(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := fcontextFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("target", err.Error()))
	}
	return diags
}

func planSELinuxFcontext(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "selinux_fcontext", []string{"target"}, []string{"setype"})
}

func readSELinuxFcontext(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		f := fcontextFrom(prior)
		ty, err := selinux.ReadFcontext(ctx, h, f)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, ty == f.Type), nil
	})
}

func applySELinuxFcontext(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			f := fcontextFrom(planned)
			if err := selinux.ApplyFcontext(ctx, h, f); err != nil {
				return cty.NilVal, fmt.Errorf("selinux_fcontext %s: %w", f.Target, err)
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return selinux.DeleteFcontext(ctx, h, fcontextFrom(prior))
		})
}

func selinuxModeSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "The host's SELinux mode, enforcing or permissive, in " + selinux.ConfigFile + " and, while SELinux is on, now. Removing it leaves the mode as it is.",
		Attributes: map[string]*configschema.Attribute{
			"id":              {Type: cty.String, Computed: true},
			"revision":        revisionAttr(),
			"mode":            {Type: cty.String, Required: true, Description: "\"enforcing\" or \"permissive\". Switching between them takes effect at once. Disabling SELinux isn't a mode here yet."},
			"reboot_required": {Type: cty.Bool, Computed: true, Description: "Whether the host needs a reboot to run in mode: true when SELinux is off now, since only a boot turns it on. Pair it with a reboot step."},
			"in_sync":         {Type: cty.Bool, Computed: true, Description: "Whether the config file has mode and, while SELinux is on, it's running in it."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateSELinuxMode(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.GetAttr("mode").IsKnown() {
		return diags
	}
	if err := selinux.ValidateMode(cfg.GetAttr("mode").AsString()); err != nil {
		diags = diags.Append(attrError("mode", err.Error()))
	}
	return diags
}

func planSELinuxMode(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	resp := planSynced(req, "selinux_mode", nil, []string{"mode"})
	if p := resp.PlannedState; !p.IsNull() && !p.GetAttr("in_sync").IsKnown() {
		vals := p.AsValueMap()
		vals["reboot_required"] = cty.UnknownVal(cty.Bool)
		resp.PlannedState = cty.ObjectVal(vals)
	}
	return resp
}

func withReboot(v cty.Value, reboot bool) cty.Value {
	vals := v.AsValueMap()
	vals["reboot_required"] = cty.BoolVal(reboot)
	return cty.ObjectVal(vals)
}

func readSELinuxMode(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		s, err := selinux.ReadMode(ctx, h)
		if err != nil {
			return cty.NilVal, err
		}
		mode := prior.GetAttr("mode").AsString()
		return withSync(withReboot(prior, s.RebootRequired(mode)), s.Matches(mode)), nil
	})
}

func applySELinuxMode(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			reboot, err := selinux.ApplyMode(ctx, h, planned.GetAttr("mode").AsString())
			if err != nil {
				return cty.NilVal, fmt.Errorf("selinux_mode: %w", err)
			}
			return withSync(withReboot(planned, reboot), true), nil
		}, nil)
}
