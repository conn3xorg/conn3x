// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/acl"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func aclSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "One POSIX ACL entry on a file or directory, such as read access for one more user, kept with getfacl and setfacl. Other entries are left as they are.",
		Attributes: map[string]*configschema.Attribute{
			"id":          {Type: cty.String, Computed: true},
			"revision":    revisionAttr(),
			"path":        {Type: cty.String, Required: true, Description: "The file or directory, absolute. It must exist."},
			"etype":       {Type: cty.String, Required: true, Description: "\"user\", \"group\", \"mask\" or \"other\"."},
			"entity":      {Type: cty.String, Optional: true, Description: "The user or group the entry is for, by name or number. Required for user and group, not set for mask and other. The owner's and the owning group's own entries are the mode, set with a file or directory step."},
			"permissions": {Type: cty.String, Optional: true, Description: "Any of r, w and x, such as \"rx\". Unset or \"\" is none, which still gives the entry, so it can take away what the group or other entry would give."},
			"default":     {Type: cty.Bool, Optional: true, Description: "true sets the directory's default ACL, which files made in it later inherit, instead of its own."},
			"state":       {Type: cty.String, Optional: true, Description: "\"present\" (default) or \"absent\", to take a user or group entry out."},
			"on_remove":   {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the entry, \"delete\" takes a user or group entry out."},
			"in_sync":     {Type: cty.Bool, Computed: true, Description: "Whether the entry was as it should be at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func aclFrom(v cty.Value) acl.Entry {
	return acl.Entry{
		Path: stringOr(v.GetAttr("path"), ""), Type: stringOr(v.GetAttr("etype"), ""), Entity: stringOr(v.GetAttr("entity"), ""),
		Permissions: stringOr(v.GetAttr("permissions"), ""), Default: boolOr(v.GetAttr("default")),
		Absent: stringOr(v.GetAttr("state"), "present") == "absent",
	}
}

func validateACL(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if s := stringOr(cfg.GetAttr("state"), "present"); s != "present" && s != "absent" {
		diags = diags.Append(attrError("state", fmt.Sprintf(`state must be "present" or "absent", not %q`, s)))
	}
	e := aclFrom(cfg)
	if err := e.Validate(); err != nil {
		diags = diags.Append(attrError("etype", err.Error()))
	}
	if stringOr(cfg.GetAttr("on_remove"), "forget") == onRemoveDelete && e.Type != "user" && e.Type != "group" {
		diags = diags.Append(attrError("on_remove", `on_remove = "delete" takes out a user or group entry; a path always keeps its mask and other entries`))
	}
	return diags
}

func planACL(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "acl", []string{"path", "etype", "entity", "default"}, []string{"permissions", "state"})
}

func readACL(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		e := aclFrom(prior)
		perms, ok, err := acl.Read(ctx, h, e)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, e.Matches(perms, ok)), nil
	})
}

func applyACL(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	set := func(ctx context.Context, h *hostConn, e acl.Entry) error {
		perms, ok, err := acl.Read(ctx, h, e)
		if err != nil || e.Matches(perms, ok) {
			return err
		}
		return acl.Apply(ctx, h, e)
	}
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			if err := set(ctx, h, aclFrom(planned)); err != nil {
				return cty.NilVal, fmt.Errorf("acl: %w", err)
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			e := aclFrom(prior)
			e.Absent = true
			return set(ctx, h, e)
		})
}
