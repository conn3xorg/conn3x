// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/container"
	"github.com/opentofu/opentofu/internal/providers"
)

func composeProjectSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A Compose project kept up with docker compose on Docker or podman-compose on Podman.",
		Attributes: map[string]*configschema.Attribute{
			"id":             {Type: cty.String, Computed: true},
			"revision":       revisionAttr(),
			"project_dir":    {Type: cty.String, Required: true, Description: "Absolute path of the directory holding the Compose file. Compose runs there."},
			"project_name":   {Type: cty.String, Optional: true, Description: "The project's name: lowercase letters, digits, - and _. Unset, Compose takes the directory's name."},
			"files":          {Type: cty.List(cty.String), Optional: true, Description: "Compose files, relative to project_dir or absolute, merged in order. Unset, Compose finds compose.yaml or one of its other default names."},
			"env_files":      {Type: cty.List(cty.String), Optional: true, Description: "Env files, relative to project_dir or absolute, instead of .env. podman-compose takes one."},
			"profiles":       {Type: cty.List(cty.String), Optional: true, Description: "Profiles to enable."},
			"services":       {Type: cty.List(cty.String), Optional: true, Description: "The services to keep up, stop or take down. Unset, every service the files and profiles enable."},
			"content":        {Type: cty.String, Optional: true, Description: "The Compose file itself. Set, Conn3x writes it, mode 0600, to the one file in files, or compose.yaml in project_dir, and a change to it plans an up. Unset, the files must be on the host already."},
			"state":          {Type: cty.String, Optional: true, Description: "\"present\" (default) keeps every service running, \"stopped\" keeps them created and stopped, \"absent\" takes them down. Volumes stay either way."},
			"pull":           {Type: cty.String, Optional: true, Description: "\"policy\" (default) follows each service's pull_policy, \"always\" pulls on every up, \"missing\" pulls only images that aren't there, \"never\" doesn't pull (Docker only)."},
			"remove_orphans": {Type: cty.Bool, Optional: true, Description: "Remove containers of services no longer in the files. Default false: they're left running."},
			"wait":           {Type: cty.Bool, Optional: true, Description: "Wait for services to be running or healthy after an up (Docker only). Default false."},
			"engine":         {Type: cty.String, Optional: true, Description: engineDoc + " Docker runs docker compose; Podman runs podman-compose."},
			"on_remove":      {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the project running, \"delete\" runs compose down. Volumes and files stay either way."},
			"config_hash":    {Type: cty.String, Computed: true, Description: "SHA-256 over the Compose and env files at the last apply. A different one at refresh plans an up."},
			"in_sync":        {Type: cty.Bool, Computed: true, Description: "Whether the services were as state says, and the files unchanged, at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func composeProjectFrom(v cty.Value) container.Compose {
	return container.Compose{
		Engine: stringOr(v.GetAttr("engine"), ""), ProjectDir: stringOr(v.GetAttr("project_dir"), ""), ProjectName: stringOr(v.GetAttr("project_name"), ""),
		Files: stringList(v.GetAttr("files")), EnvFiles: stringList(v.GetAttr("env_files")), Profiles: stringList(v.GetAttr("profiles")), Services: stringList(v.GetAttr("services")),
		State: stringOr(v.GetAttr("state"), ""), Pull: stringOr(v.GetAttr("pull"), ""), Content: stringOr(v.GetAttr("content"), ""),
		RemoveOrphans: boolOr(v.GetAttr("remove_orphans")), Wait: boolOr(v.GetAttr("wait")),
	}
}

func planComposeProject(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	resp := planSynced(req, "compose_project", []string{"project_dir", "project_name"},
		[]string{"files", "env_files", "profiles", "services", "content", "state", "pull", "remove_orphans", "wait", "engine"})
	// The apply records the files' new hash.
	if p := resp.PlannedState; !p.IsNull() && !p.GetAttr("in_sync").IsKnown() {
		vals := p.AsValueMap()
		vals["config_hash"] = cty.UnknownVal(cty.String)
		resp.PlannedState = cty.ObjectVal(vals)
	}
	return resp
}

func readComposeProject(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		c := composeProjectFrom(prior)
		a, err := container.ReadCompose(ctx, h, c)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, len(c.Differences(a, stringOr(prior.GetAttr("config_hash"), ""))) == 0), nil
	})
}

func applyComposeProject(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			hash, err := container.ApplyCompose(ctx, h, composeProjectFrom(planned))
			if err != nil {
				return cty.NilVal, err
			}
			vals := withSync(planned, true).AsValueMap()
			vals["config_hash"] = cty.StringVal(hash)
			return cty.ObjectVal(vals), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return container.DeleteCompose(ctx, h, composeProjectFrom(prior))
		})
}
