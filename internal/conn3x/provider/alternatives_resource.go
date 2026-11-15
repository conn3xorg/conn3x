// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/alternatives"
	"github.com/opentofu/opentofu/internal/providers"
)

func alternativesSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Which program a generic name such as editor or python3 runs, through update-alternatives on the Debian family and alternatives on the Red Hat family.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"name":      {Type: cty.String, Required: true, Description: "The generic name, such as editor, java or python."},
			"path":      {Type: cty.String, Required: true, Description: "The program the name should run, such as /usr/bin/vim.basic."},
			"link":      {Type: cty.String, Optional: true, Description: "The generic link, such as /usr/bin/editor. Needed to register a name the host doesn't know yet, and on the Red Hat family to register a new path."},
			"priority":  {Type: cty.Number, Optional: true, Description: "Priority path is registered with; higher wins in auto mode. Defaults to " + alternatives.DefaultPriority + ". Set it to change a registered path's priority."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the choice, \"delete\" removes path from the name's choices."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the name points to path, registered with priority when set."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func alternativeFrom(v cty.Value) alternatives.Alternative {
	a := alternatives.Alternative{Name: v.GetAttr("name").AsString(), Path: v.GetAttr("path").AsString(), Link: stringOr(v.GetAttr("link"), "")}
	if p := v.GetAttr("priority"); !p.IsNull() {
		a.Priority = p.AsBigFloat().Text('f', -1)
	}
	return a
}

func planAlternatives(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "alternatives", []string{"name"}, []string{"path", "link", "priority"})
}

func readAlternatives(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		a := alternativeFrom(prior)
		act, err := alternatives.Read(ctx, h, a)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, a.InSync(act)), nil
	})
}

func applyAlternatives(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			a := alternativeFrom(planned)
			if err := alternatives.Apply(ctx, h, a); err != nil {
				return cty.NilVal, fmt.Errorf("alternatives %s: %w", a.Name, err)
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return alternatives.Delete(ctx, h, alternativeFrom(prior))
		})
}
