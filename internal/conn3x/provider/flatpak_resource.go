// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/flatpak"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// defaultFlatpakRemote is where an app comes from when the step doesn't say,
// as Ansible's flatpak module assumes.
const defaultFlatpakRemote = "flathub"

func flatpakSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "An application or runtime from a Flatpak remote such as Flathub, in the system installation or the connecting user's.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"name":      {Type: cty.String, Required: true, Description: "Application ID, such as org.gnome.Calculator."},
			"remote":    {Type: cty.String, Optional: true, Description: "Remote to install from, which the host must already have. Defaults to " + defaultFlatpakRemote + "."},
			"method":    {Type: cty.String, Optional: true, Description: "\"system\" (default) for every user on the host, or \"user\" for the connecting user's own installation."},
			"state":     {Type: cty.String, Optional: true, Description: "\"present\" (default), \"latest\" or \"absent\"."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this step is removed: \"forget\" (default) leaves the app, \"delete\" uninstalls it."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the app is installed, or not, as wanted, and with state \"latest\" as new as the remote has."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func desiredFlatpak(v cty.Value) flatpak.Desired {
	return flatpak.Desired{
		Name:   v.GetAttr("name").AsString(),
		Remote: stringOr(v.GetAttr("remote"), defaultFlatpakRemote),
		Method: flatpak.Method(stringOr(v.GetAttr("method"), string(flatpak.System))),
		State:  flatpak.State(stringOr(v.GetAttr("state"), string(flatpak.Present))),
	}
}

func validateFlatpak(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	d := desiredFlatpak(cfg)
	if s := d.State; s != flatpak.Present && s != flatpak.Latest && s != flatpak.Absent {
		return diags.Append(attrError("state", fmt.Sprintf("state must be \"present\", \"latest\" or \"absent\", not %q", s)))
	}
	if m := d.Method; m != flatpak.System && m != flatpak.User {
		return diags.Append(attrError("method", fmt.Sprintf("method must be \"system\" or \"user\", not %q", m)))
	}
	if err := d.Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planFlatpak(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "flatpak", []string{"name", "method"}, []string{"remote", "state"})
}

func readFlatpak(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		d := desiredFlatpak(prior)
		a, err := flatpak.Read(ctx, h, d)
		if err != nil {
			return cty.NilVal, fmt.Errorf("reading flatpak %s: %w", d.Name, err)
		}
		return withSync(prior, d.InSync(a)), nil
	})
}

func applyFlatpak(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			d := desiredFlatpak(planned)
			// Two installs into one installation fight over its lock, and
			// a for_each runs them together.
			defer lockHost(h, "flatpak\x00"+string(d.Method))()
			if err := flatpak.Apply(ctx, h, d); err != nil {
				return cty.NilVal, fmt.Errorf("flatpak %s: %w", d.Name, err)
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			d := desiredFlatpak(prior)
			d.State = flatpak.Absent
			defer lockHost(h, "flatpak\x00"+string(d.Method))()
			if err := flatpak.Apply(ctx, h, d); err != nil {
				return fmt.Errorf("flatpak %s: %w", d.Name, err)
			}
			return nil
		})
}
