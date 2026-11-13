// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/kmod"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func modprobeSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A kernel module, loaded with its parameters and kept loaded across reboots.",
		Attributes: map[string]*configschema.Attribute{
			"id":         {Type: cty.String, Computed: true},
			"revision":   revisionAttr(),
			"name":       {Type: cty.String, Required: true, Description: "The module, such as br_netfilter or wireguard."},
			"params":     {Type: cty.List(cty.String), Optional: true, Description: "Parameters, each key=value, such as [\"numdummies=2\"]. A module loaded with other values is unloaded and loaded again."},
			"state":      {Type: cty.String, Optional: true, Description: "\"present\" (default) loads the module, \"absent\" unloads it."},
			"persistent": {Type: cty.Bool, Optional: true, Description: "Keep it so at boot: /etc/modules-load.d/<name>.conf loads it, and /etc/modprobe.d/<name>.conf holds its params; with state \"absent\", both are removed. Defaults to true. false leaves those files alone."},
			"on_remove":  {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the module loaded, \"delete\" unloads it and removes its boot files."},
			"in_sync":    {Type: cty.Bool, Computed: true, Description: "Whether the module is loaded, or not, as wanted, with its params and boot files."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func modprobeFrom(v cty.Value) kmod.Module {
	m := kmod.Module{Name: v.GetAttr("name").AsString(), Params: stringList(v.GetAttr("params")), Absent: stringOr(v.GetAttr("state"), "present") == "absent", Persistent: true}
	if p := v.GetAttr("persistent"); known(p) {
		m.Persistent = p.True()
	}
	return m
}

func validateModprobe(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if s := stringOr(cfg.GetAttr("state"), "present"); s != "present" && s != "absent" {
		return diags.Append(attrError("state", fmt.Sprintf("state must be \"present\" or \"absent\", not %q", s)))
	}
	if err := modprobeFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planModprobe(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "modprobe", []string{"name"}, []string{"params", "state", "persistent"})
}

func readModprobe(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		m := modprobeFrom(prior)
		a, err := kmod.Read(ctx, h, m)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, m.InSync(a)), nil
	})
}

func applyModprobe(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			if err := kmod.Apply(ctx, h, modprobeFrom(planned)); err != nil {
				return cty.NilVal, err
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			m := modprobeFrom(prior)
			m.Params, m.Absent, m.Persistent = nil, true, true
			return kmod.Apply(ctx, h, m)
		})
}
