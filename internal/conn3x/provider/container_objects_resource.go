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

const engineDoc = "\"docker\" or \"podman\". Unset, Conn3x uses Docker if it's installed, and Podman otherwise."

func containerImageSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "An image pulled with Docker or Podman and kept on the host.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"name":      {Type: cty.String, Required: true, Description: "The image, such as docker.io/library/nginx, or with its tag or digest, such as docker.io/library/nginx:1.30 or docker.io/library/nginx@sha256:... Write it as the container step's image is written, so the two name the same image."},
			"tag":       {Type: cty.String, Optional: true, Description: "The tag, such as 1.30, when name has none. Unset, the engine pulls latest."},
			"engine":    {Type: cty.String, Optional: true, Description: engineDoc},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the image, \"delete\" removes it. The engine won't remove an image a container uses, so remove the container first."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the image was on the host at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func containerImageFrom(v cty.Value) container.Image {
	return container.Image{Name: stringOr(v.GetAttr("name"), ""), Tag: stringOr(v.GetAttr("tag"), ""), Engine: stringOr(v.GetAttr("engine"), "")}
}

func planContainerImage(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "container_image", []string{"name", "tag"}, []string{"engine"})
}

func readContainerImage(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		a, err := container.ReadImage(ctx, h, containerImageFrom(prior))
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, a.Exists), nil
	})
}

func applyContainerImage(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			if err := container.ApplyImage(ctx, h, containerImageFrom(planned)); err != nil {
				return cty.NilVal, err
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return container.DeleteImage(ctx, h, containerImageFrom(prior))
		})
}

func containerNetworkSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A network made with Docker or Podman, for containers to join by name.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"name":      {Type: cty.String, Required: true, Description: "The network's name."},
			"driver":    {Type: cty.String, Optional: true, Description: "\"bridge\" (default), \"macvlan\" or \"ipvlan\"."},
			"subnet":    {Type: cty.String, Optional: true, Description: "The subnet, such as 10.89.0.0/24. Unset, the engine picks one, and any it picked is fine."},
			"engine":    {Type: cty.String, Optional: true, Description: engineDoc},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the network, \"delete\" removes it. The engine won't remove a network a container is on, so remove the container first."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the network was there with this driver and subnet at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func containerNetworkFrom(v cty.Value) container.Network {
	return container.Network{Name: stringOr(v.GetAttr("name"), ""), Driver: stringOr(v.GetAttr("driver"), ""), Subnet: stringOr(v.GetAttr("subnet"), ""), Engine: stringOr(v.GetAttr("engine"), "")}
}

func planContainerNetwork(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "container_network", []string{"name"}, []string{"driver", "subnet", "engine"})
}

func readContainerNetwork(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		n := containerNetworkFrom(prior)
		a, err := container.ReadNetwork(ctx, h, n)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, len(n.Differences(a)) == 0), nil
	})
}

func applyContainerNetwork(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			if err := container.ApplyNetwork(ctx, h, containerNetworkFrom(planned)); err != nil {
				return cty.NilVal, err
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return container.DeleteNetwork(ctx, h, containerNetworkFrom(prior))
		})
}

func containerVolumeSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A named volume made with Docker or Podman, for containers to mount by name.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"name":      {Type: cty.String, Required: true, Description: "The volume's name, as a container step's volumes give it before the colon."},
			"driver":    {Type: cty.String, Optional: true, Description: "The volume driver. Defaults to \"local\". A volume already there with another driver is left alone: changing it would mean removing its data, so the apply says so instead."},
			"engine":    {Type: cty.String, Optional: true, Description: engineDoc},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the volume and its data, \"delete\" removes both. The engine won't remove a volume a container uses, so remove the container first."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the volume was there with this driver at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func containerVolumeFrom(v cty.Value) container.Volume {
	return container.Volume{Name: stringOr(v.GetAttr("name"), ""), Driver: stringOr(v.GetAttr("driver"), ""), Engine: stringOr(v.GetAttr("engine"), "")}
}

func planContainerVolume(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "container_volume", []string{"name"}, []string{"driver", "engine"})
}

func readContainerVolume(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		v := containerVolumeFrom(prior)
		a, err := container.ReadVolume(ctx, h, v)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, v.InSync(a)), nil
	})
}

func applyContainerVolume(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			if err := container.ApplyVolume(ctx, h, containerVolumeFrom(planned)); err != nil {
				return cty.NilVal, err
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return container.DeleteVolume(ctx, h, containerVolumeFrom(prior))
		})
}
