// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/mount"
	"github.com/opentofu/opentofu/internal/providers"
)

func swapSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Swap space, a file Conn3x makes or a device that's already swap, on now and in /etc/fstab.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"path":      {Type: cty.String, Required: true, Description: "The swap file, such as /swapfile, or a device, such as /dev/vdb or /dev/disk/by-uuid/...."},
			"size":      {Type: cty.String, Optional: true, Description: "Makes path a swap file of this size, such as \"2G\" or \"512M\", and makes it again when the size changes. Leave it unset for a device or a file that's already swap; Conn3x won't format either, since that wipes what's there."},
			"priority":  {Type: cty.Number, Optional: true, Description: "From -1 to 32767; higher is used first. Unset leaves it to the kernel."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the swap on, \"delete\" turns it off, removes the fstab entry and, for a swap file Conn3x made, the file."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the fstab entry matches, the swap is on with its priority, and a swap file has its size."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func swapFrom(v cty.Value) mount.Swap {
	s := mount.Swap{Path: v.GetAttr("path").AsString(), Size: stringOr(v.GetAttr("size"), "")}
	if p := v.GetAttr("priority"); !p.IsNull() {
		s.Priority = p.AsBigFloat().Text('f', -1)
	}
	return s
}

func planSwap(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "swap", []string{"path"}, []string{"size", "priority"})
}

func readSwap(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		s := swapFrom(prior)
		a, err := mount.ReadSwap(ctx, h, s)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, s.InSync(a)), nil
	})
}

func applySwap(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			s := swapFrom(planned)
			if err := mount.ApplySwap(ctx, h, s); err != nil {
				return cty.NilVal, fmt.Errorf("swap %s: %w", s.Path, err)
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return mount.DeleteSwap(ctx, h, swapFrom(prior))
		})
}
