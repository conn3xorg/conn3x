// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/storage"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// The storage steps have no on_remove: taking one out of a circuit leaves
// the host's disks as they are, since undoing any of them destroys data.

func filesystemSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A file system on a block device, made if the device holds none.",
		Attributes: map[string]*configschema.Attribute{
			"id":       {Type: cty.String, Computed: true},
			"revision": revisionAttr(),
			"device":   {Type: cty.String, Required: true, Description: "The block device, such as /dev/sdb or /dev/vg0/data."},
			"type":     {Type: cty.String, Required: true, Description: "The file system: " + strings.Join(storage.FilesystemTypes(), ", ") + "."},
			"opts":     {Type: cty.List(cty.String), Optional: true, Description: "Extra mkfs options, one word each, such as [\"-L\", \"data\"]. Used only when the file system is made."},
			"resize":   {Type: cty.Bool, Optional: true, Description: "Grow the file system to fill its device when the device grows. For ext2, ext3, ext4 and xfs; xfs grows only while mounted."},
			"force":    {Type: cty.Bool, Optional: true, Description: "Make the file system over whatever else the device holds, erasing it. Never over a mounted one."},
			"in_sync":  {Type: cty.Bool, Computed: true, Description: "Whether the device holds the file system, grown to fill it with resize."},
			"earlier_revisions": {Type: cty.DynamicPseudoType, Optional: true, Description: "Set by the circuit when resize is set, so leave it unset: the revisions of the steps before this one. A plan that changes any of them checks the file system's size again at apply time, so a volume an earlier step grows gets its file system grown in the same apply."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

// planFilesystem is planSynced, and with resize, stale whenever an earlier
// step is about to change, since it may grow the device after the refresh
// read its size.
func planFilesystem(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	resp := planSynced(req, "filesystem", []string{"device"}, []string{"type", "resize", "force", "opts"})
	if req.PriorState.IsNull() || resp.PlannedState.IsNull() || !boolOr(resp.PlannedState.GetAttr("resize")) {
		return resp
	}
	earlier, was := resp.PlannedState.GetAttr("earlier_revisions"), req.PriorState.GetAttr("earlier_revisions")
	if !earlier.IsWhollyKnown() || !was.RawEquals(earlier) {
		vals := resp.PlannedState.AsValueMap()
		vals["in_sync"] = cty.UnknownVal(cty.Bool)
		resp.PlannedState = cty.ObjectVal(vals)
	}
	return resp
}

func filesystemFrom(v cty.Value) storage.Filesystem {
	return storage.Filesystem{
		Device: v.GetAttr("device").AsString(), Type: v.GetAttr("type").AsString(), Opts: stringList(v.GetAttr("opts")),
		Resize: boolOr(v.GetAttr("resize")), Force: boolOr(v.GetAttr("force")),
	}
}

func volumeGroupSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "An LVM volume group on physical volumes.",
		Attributes: map[string]*configschema.Attribute{
			"id":       {Type: cty.String, Computed: true},
			"revision": revisionAttr(),
			"name":     {Type: cty.String, Required: true, Description: "The volume group's name, such as vg0."},
			"pvs":      {Type: cty.List(cty.String), Required: true, Description: "The devices in it, such as [\"/dev/sdb\"]. A device that isn't a physical volume yet becomes one. One in the group but not listed stays in it."},
			"force":    {Type: cty.Bool, Optional: true, Description: "Take in a device that holds a file system, erasing it. Never one that's mounted, or in another volume group."},
			"in_sync":  {Type: cty.Bool, Computed: true, Description: "Whether the group exists with every device in pvs."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func volumeGroupFrom(v cty.Value) storage.VolumeGroup {
	return storage.VolumeGroup{Name: v.GetAttr("name").AsString(), PVs: stringList(v.GetAttr("pvs")), Force: boolOr(v.GetAttr("force"))}
}

func logicalVolumeSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "An LVM logical volume, grown to its size.",
		Attributes: map[string]*configschema.Attribute{
			"id":       {Type: cty.String, Computed: true},
			"revision": revisionAttr(),
			"vg":       {Type: cty.String, Required: true, Description: "The volume group it's in."},
			"name":     {Type: cty.String, Required: true, Description: "The volume's name. Its device is /dev/<vg>/<name>."},
			"size":     {Type: cty.String, Required: true, Description: "Its size: 512m, 20g or 1.5t (binary units; a bare number is MiB), a share of the group such as 50%VG, or a share of its free space such as 100%FREE, which sizes the volume only when it's made."},
			"force":    {Type: cty.Bool, Optional: true, Description: "Shrink the volume when it's bigger than size, destroying whatever is past the new end, file system included."},
			"in_sync":  {Type: cty.Bool, Computed: true, Description: "Whether the volume exists at its size."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func logicalVolumeFrom(v cty.Value) storage.LogicalVolume {
	return storage.LogicalVolume{VG: v.GetAttr("vg").AsString(), Name: v.GetAttr("name").AsString(), Size: v.GetAttr("size").AsString(), Force: boolOr(v.GetAttr("force"))}
}

// boolOr is a bool attribute, false when unset.
func boolOr(v cty.Value) bool { return v.IsKnown() && !v.IsNull() && v.True() }

// validateForce warns, at every plan, that force is on, since it lets the
// step destroy data.
func validateForce(what string, check func(cty.Value) error, attr string) func(cty.Value) tfdiags.Diagnostics {
	base := validateWith(attr, check)
	return func(cfg cty.Value) tfdiags.Diagnostics {
		diags := base(cfg)
		if cfg.IsNull() || !cfg.IsWhollyKnown() || !boolOr(cfg.GetAttr("force")) {
			return diags
		}
		return diags.Append(tfdiags.AttributeValue(tfdiags.Warning, "force can destroy data",
			"With force = true, this step "+what+". Take force off once the change it was for is applied.", cty.GetAttrPath("force")))
	}
}

var storageTypes = map[string]resourceType{
	"conn3x_filesystem": {filesystemSchema, validateForce("makes its file system over any other file system on the device, erasing it", func(v cty.Value) error { return filesystemFrom(v).Validate() }, "device"),
		planFilesystem,
		func(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
			return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
				f := filesystemFrom(prior)
				a, err := storage.ReadFilesystem(ctx, h, f)
				if err != nil {
					return cty.NilVal, err
				}
				return withSync(prior, f.InSync(a)), nil
			})
		},
		func(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
			return applyPathResource(ctx, req, func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
				if err := storage.ApplyFilesystem(ctx, h, filesystemFrom(planned)); err != nil {
					return cty.NilVal, err
				}
				return withSync(planned, true), nil
			}, func(context.Context, *hostConn, cty.Value) error { return nil })
		},
		upgradeWith(filesystemSchema)},
	"conn3x_lvm_volume_group": {volumeGroupSchema, validateForce("erases any file system on a device it adds", func(v cty.Value) error { return volumeGroupFrom(v).Validate() }, "pvs"),
		func(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
			return planSynced(req, "lvm_volume_group", []string{"name"}, []string{"pvs", "force"})
		},
		func(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
			return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
				g := volumeGroupFrom(prior)
				a, err := storage.ReadVolumeGroup(ctx, h, g)
				if err != nil {
					return cty.NilVal, err
				}
				return withSync(prior, g.InSync(a)), nil
			})
		},
		func(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
			return applyPathResource(ctx, req, func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
				if err := storage.ApplyVolumeGroup(ctx, h, volumeGroupFrom(planned)); err != nil {
					return cty.NilVal, err
				}
				return withSync(planned, true), nil
			}, func(context.Context, *hostConn, cty.Value) error { return nil })
		},
		upgradeWith(volumeGroupSchema)},
	"conn3x_lvm_logical_volume": {logicalVolumeSchema, validateForce("shrinks the volume when it's bigger than size, destroying what's past the new end", func(v cty.Value) error { return logicalVolumeFrom(v).Validate() }, "size"),
		func(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
			return planSynced(req, "lvm_logical_volume", []string{"vg", "name"}, []string{"size", "force"})
		},
		func(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
			return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
				l := logicalVolumeFrom(prior)
				a, err := storage.ReadLogicalVolume(ctx, h, l)
				if err != nil {
					return cty.NilVal, err
				}
				return withSync(prior, l.InSync(a)), nil
			})
		},
		func(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
			return applyPathResource(ctx, req, func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
				if err := storage.ApplyLogicalVolume(ctx, h, logicalVolumeFrom(planned)); err != nil {
					return cty.NilVal, err
				}
				return withSync(planned, true), nil
			}, func(context.Context, *hostConn, cty.Value) error { return nil })
		},
		upgradeWith(logicalVolumeSchema)},
}
