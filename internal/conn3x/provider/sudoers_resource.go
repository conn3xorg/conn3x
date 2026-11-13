// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/modules/sudoers"
	"github.com/opentofu/opentofu/internal/providers"
)

func sudoersSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A sudo rule in its own file in /etc/sudoers.d, checked with visudo before it's written.",
		Attributes: map[string]*configschema.Attribute{
			"id":         {Type: cty.String, Computed: true},
			"revision":   revisionAttr(),
			"name":       {Type: cty.String, Required: true, Description: "The file's name in /etc/sudoers.d: letters, digits, _ and -. sudo skips a name with a dot or ending in ~."},
			"user":       {Type: cty.String, Optional: true, Description: "The user the rule is for. Set this or group."},
			"group":      {Type: cty.String, Optional: true, Description: "The group the rule is for. Set this or user."},
			"commands":   {Type: cty.List(cty.String), Required: true, Description: "The commands, each an absolute path with any arguments, such as /usr/bin/systemctl restart app, or [\"ALL\"]."},
			"runas":      {Type: cty.String, Optional: true, Description: "Who the commands run as: a user, user:group, or ALL (the default)."},
			"nopassword": {Type: cty.Bool, Optional: true, Description: "Let the commands run without the user's password. Defaults to false."},
			"host":       {Type: cty.String, Optional: true, Description: "The host the rule applies on, or ALL (the default)."},
			"on_remove":  {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the rule in place, \"delete\" removes its file."},
			"in_sync":    {Type: cty.Bool, Computed: true, Description: "Whether the file holds the rule, owned by root with mode 0440."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func sudoersFrom(v cty.Value) sudoers.Rule {
	return sudoers.Rule{
		Name: v.GetAttr("name").AsString(), User: stringOr(v.GetAttr("user"), ""), Group: stringOr(v.GetAttr("group"), ""),
		Commands: stringList(v.GetAttr("commands")), RunAs: stringOr(v.GetAttr("runas"), ""), Host: stringOr(v.GetAttr("host"), ""),
		NoPassword: known(v.GetAttr("nopassword")) && v.GetAttr("nopassword").True(),
	}
}

func planSudoers(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "sudoers", []string{"name"}, []string{"user", "group", "commands", "runas", "nopassword", "host"})
}

func readSudoers(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		r := sudoersFrom(prior)
		a, err := sudoers.Read(ctx, h, r)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, r.InSync(a)), nil
	})
}

func applySudoers(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			if err := sudoers.Apply(ctx, h, sudoersFrom(planned)); err != nil {
				return cty.NilVal, err
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return file.Delete(ctx, h, sudoersFrom(prior).Path())
		})
}
