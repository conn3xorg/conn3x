// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func packageHoldSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Holds a package back from updates, or releases it: apt-mark hold on Debian and Ubuntu, dnf versionlock on the Red Hat family. It doesn't install the package.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"name":      {Type: cty.String, Required: true, Description: "Package name, such as kernel or postgresql16-server."},
			"state":     {Type: cty.String, Optional: true, Description: "\"held\" (default) keeps the package at its version through updates; \"released\" lets it update again."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the hold as it is, \"delete\" releases it."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the package was held, or released, as it should be at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func packageHoldFrom(v cty.Value) pkg.Hold {
	return pkg.Hold{Name: v.GetAttr("name").AsString(), Held: stringOr(v.GetAttr("state"), "held") == "held"}
}

func validatePackageHold(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if s := stringOr(cfg.GetAttr("state"), "held"); s != "held" && s != "released" {
		diags = diags.Append(attrError("state", fmt.Sprintf(`state must be "held" or "released", not %q`, s)))
	}
	if err := packageHoldFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planPackageHold(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "package_hold", []string{"name"}, []string{"state"})
}

func readPackageHold(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		want := packageHoldFrom(prior)
		family, err := pkg.DetectFamily(ctx, h)
		if err != nil {
			return cty.NilVal, err
		}
		held, err := pkg.ReadHold(ctx, h, family, want.Name)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, held == want.Held), nil
	})
}

func applyPackageHold(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	set := func(ctx context.Context, h *hostConn, want pkg.Hold) error {
		family, err := pkg.DetectFamily(ctx, h)
		if err != nil {
			return err
		}
		if held, err := pkg.ReadHold(ctx, h, family, want.Name); err != nil || held == want.Held {
			return err
		}
		if err := pkg.ApplyHold(ctx, h, family, want); err != nil {
			return fmt.Errorf("package_hold %s: %w", want.Name, err)
		}
		return nil
	}
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			if err := set(ctx, h, packageHoldFrom(planned)); err != nil {
				return cty.NilVal, err
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			release := packageHoldFrom(prior)
			release.Held = false
			return set(ctx, h, release)
		})
}
