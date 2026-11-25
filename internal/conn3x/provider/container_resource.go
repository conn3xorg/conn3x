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

func containerSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A container kept running with Docker or Podman.",
		Attributes: map[string]*configschema.Attribute{
			"id":          {Type: cty.String, Computed: true},
			"revision":    revisionAttr(),
			"name":        {Type: cty.String, Required: true, Description: "The container's name."},
			"image":       {Type: cty.String, Required: true, Description: "The image, such as docker.io/library/nginx:1.30. Write it in full: a new tag recreates the container, and a new digest behind the same tag doesn't."},
			"ports":       {Type: cty.List(cty.String), Optional: true, Description: "Published ports, each host:container, such as 8080:80, optionally with an address in front and /tcp, /udp or /sctp after."},
			"volumes":     {Type: cty.List(cty.String), Optional: true, Description: "Mounts, each source:destination[:options], with an absolute host path or a volume name as the source. Options are ro, rw, z and Z."},
			"networks":    {Type: cty.List(cty.String), Optional: true, Description: "Networks to join, by name, such as one a container_network step made. Unset, the container is on the engine's default network."},
			"env":         {Type: cty.Map(cty.String), Optional: true, Sensitive: true, Description: "Environment variables. Passed on standard input, not the command line, so they don't show in the host's process list. Only the ones you set are compared."},
			"restart":     {Type: cty.String, Optional: true, Description: "Restart policy: \"no\" (default), \"always\", \"unless-stopped\" or \"on-failure\". With Podman, always and unless-stopped also enable podman-restart.service, so the container starts after a reboot."},
			"command":     {Type: cty.List(cty.String), Optional: true, Description: "The command to run instead of the image's own, one argument per entry."},
			"user":        {Type: cty.String, Optional: true, Description: "The user to run as, by name or id, optionally with :group after, such as \"1000:1000\". Unset, the image's user."},
			"labels":      {Type: cty.Map(cty.String), Optional: true, Description: "Labels on the container, such as { \"traefik.enable\" = \"true\" }. Only the ones you set are compared, since the image adds its own."},
			"memory":      {Type: cty.String, Optional: true, Description: "Memory limit, such as \"512m\" or \"2g\": a number with b, k, m, g, t or p after, in powers of 1024. Unset, no limit."},
			"cpus":        {Type: cty.Number, Optional: true, Description: "How many CPUs the container can use, such as 1.5. Unset or 0, no limit."},
			"log_driver":  {Type: cty.String, Optional: true, Description: "Logging driver, such as \"json-file\", \"local\" or \"journald\". Unset, the engine's default. Podman takes json-file as another name for k8s-file."},
			"log_options": {Type: cty.Map(cty.String), Optional: true, Description: "Options for log_driver, such as { \"max-size\" = \"10m\" }. Only the ones you set are compared. Podman shows only path, tag and max-size, so a hand change to any other doesn't show as drift there."},
			"engine":      {Type: cty.String, Optional: true, Description: "\"docker\" or \"podman\". Unset, Conn3x uses Docker if it's installed, and Podman otherwise."},
			"on_remove":   {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the container running, \"delete\" removes it. Its volumes stay either way."},
			"in_sync":     {Type: cty.Bool, Computed: true, Description: "Whether the container runs with these settings."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func containerFrom(v cty.Value) container.Container {
	c := container.Container{
		Name: v.GetAttr("name").AsString(), Image: v.GetAttr("image").AsString(),
		Ports: stringList(v.GetAttr("ports")), Volumes: stringList(v.GetAttr("volumes")), Command: stringList(v.GetAttr("command")), Networks: stringList(v.GetAttr("networks")),
		Restart: stringOr(v.GetAttr("restart"), ""), Engine: stringOr(v.GetAttr("engine"), ""),
	}
	c.Env, c.Labels, c.LogOptions = stringMap(v.GetAttr("env")), stringMap(v.GetAttr("labels")), stringMap(v.GetAttr("log_options"))
	c.User, c.Memory, c.LogDriver = stringOr(v.GetAttr("user"), ""), stringOr(v.GetAttr("memory"), ""), stringOr(v.GetAttr("log_driver"), "")
	if n := v.GetAttr("cpus"); n.IsKnown() && !n.IsNull() {
		c.CPUs, _ = n.AsBigFloat().Float64()
	}
	return c
}

func planContainer(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "container", []string{"name"}, []string{"image", "ports", "volumes", "networks", "env", "restart", "command", "engine", "user", "labels", "memory", "cpus", "log_driver", "log_options"})
}

func readContainer(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		c := containerFrom(prior)
		a, err := container.Read(ctx, h, c)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, c.InSync(a)), nil
	})
}

func applyContainer(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			if err := container.Apply(ctx, h, containerFrom(planned)); err != nil {
				return cty.NilVal, err
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return container.Delete(ctx, h, containerFrom(prior))
		})
}
