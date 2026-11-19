// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/mount"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
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
			"dump":      {Type: cty.Number, Optional: true, Description: "fstab's dump field: 1 lets dump(8) back the file system up, 0 (default) leaves it alone."},
			"passno":    {Type: cty.Number, Optional: true, Description: "fstab's fsck pass: 0 (default) never checks the file system at boot, 1 checks it before the others, 2 after them. A data disk wants 2."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves it mounted, \"delete\" unmounts it and removes the fstab entry."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the fstab entry matches and it is mounted."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func mountFrom(v cty.Value) mount.Mount {
	return mount.Mount{Path: v.GetAttr("path").AsString(), Src: v.GetAttr("src").AsString(), FSType: v.GetAttr("fstype").AsString(),
		Opts: stringOr(v.GetAttr("opts"), ""), Dump: intOr(v.GetAttr("dump"), 0), PassNo: intOr(v.GetAttr("passno"), 0)}
}

func planMount(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "mount", []string{"path"}, []string{"src", "fstype", "opts", "dump", "passno"})
}

// validateMount points each failure at the fstab field it's about, rather
// than at path as every one of them used to be.
func validateMount(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	for _, k := range []string{"dump", "passno"} {
		if v := cfg.GetAttr(k); !v.IsNull() && !v.AsBigFloat().IsInt() {
			return diags.Append(attrError(k, k+" must be a whole number"))
		}
	}
	attr := "path"
	err := mountFrom(cfg).Validate()
	var ve *mount.ValidationError
	if errors.As(err, &ve) {
		attr = ve.Attribute
	}
	if err != nil {
		diags = diags.Append(attrError(attr, err.Error()))
	}
	return diags
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
