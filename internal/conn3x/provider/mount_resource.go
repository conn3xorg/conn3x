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

func mountSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A file system in /etc/fstab, mounted now.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"path":      {Type: cty.String, Required: true, Description: "Mount point. Created if missing."},
			"src":       {Type: cty.String, Required: true, Description: "Device, UUID=..., LABEL=..., host:/export, or tmpfs."},
			"fstype":    {Type: cty.String, Required: true, Description: "File system type, such as xfs, ext4, nfs4 or tmpfs."},
			"opts":      {Type: cty.String, Optional: true, Description: "Mount options. Defaults to \"defaults\"."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves it mounted, \"delete\" unmounts it and removes the fstab entry."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the fstab entry matches and it is mounted."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func mountFrom(v cty.Value) mount.Mount {
	return mount.Mount{Path: v.GetAttr("path").AsString(), Src: v.GetAttr("src").AsString(), FSType: v.GetAttr("fstype").AsString(), Opts: stringOr(v.GetAttr("opts"), "")}
}

func planMount(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "mount", []string{"path"}, []string{"src", "fstype", "opts"})
}

func readMount(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		m := mountFrom(prior)
		a, err := mount.Read(ctx, h, m)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, m.InSync(a)), nil
	})
}

func applyMount(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			m := mountFrom(planned)
			if err := mount.Apply(ctx, h, m); err != nil {
				return cty.NilVal, fmt.Errorf("mount %s: %w", m.Path, err)
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return mount.Delete(ctx, h, mountFrom(prior))
		})
}
