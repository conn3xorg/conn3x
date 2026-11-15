// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/snap"
	"github.com/opentofu/opentofu/internal/providers"
)

func snapSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A snap, installed through snapd and kept on a channel.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"name":      {Type: cty.String, Required: true, Description: "Snap name, such as lxd or microk8s."},
			"state":     {Type: cty.String, Optional: true, Description: "\"present\" (default) or \"absent\"."},
			"channel":   {Type: cty.String, Optional: true, Description: "Channel to track, such as stable, 5.21/stable or latest/edge. Without it, a snap that's installed keeps its channel, and a new one gets the store's default, stable."},
			"classic":   {Type: cty.Bool, Optional: true, Description: "true allows classic confinement, as snap install --classic does, which snaps such as code and go need. A snap that is already classic stays so when this is false."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the snap, \"delete\" removes it."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the snap is installed on channel with the confinement asked for, or absent when state is \"absent\"."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func snapFrom(v cty.Value) snap.Snap {
	return snap.Snap{Name: v.GetAttr("name").AsString(), Channel: stringOr(v.GetAttr("channel"), ""), Classic: boolOr(v.GetAttr("classic"))}
}

func snapAbsent(v cty.Value) bool { return stringOr(v.GetAttr("state"), "present") == "absent" }

func validateSnap(v cty.Value) error {
	if st := stringOr(v.GetAttr("state"), "present"); st != "present" && st != "absent" {
		return fmt.Errorf("state must be \"present\" or \"absent\", not %q", st)
	}
	return snapFrom(v).Validate()
}

func planSnap(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "snap", []string{"name"}, []string{"state", "channel", "classic"})
}

func readSnap(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		s := snapFrom(prior)
		act, err := snap.Read(ctx, h, s.Name)
		if err != nil {
			return cty.NilVal, fmt.Errorf("snap %s: %w", s.Name, err)
		}
		if snapAbsent(prior) {
			return withSync(prior, !act.Installed), nil
		}
		return withSync(prior, s.InSync(act)), nil
	})
}

func applySnap(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			s := snapFrom(planned)
			var err error
			if snapAbsent(planned) {
				err = snap.Remove(ctx, h, s.Name)
			} else {
				err = snap.Apply(ctx, h, s)
			}
			if err != nil {
				return cty.NilVal, fmt.Errorf("snap %s: %w", s.Name, err)
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return snap.Remove(ctx, h, snapFrom(prior).Name)
		})
}
