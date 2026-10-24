// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package provider is Conn3x's built-in provider. Its resources describe
// the state of hosts: files, packages, services and users.
package provider

import (
	"context"
	"fmt"

	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// Provider implements providers.Interface in process.
type Provider struct{}

// New returns the built-in conn3x provider.
func New() (providers.Interface, error) {
	return &Provider{}, nil
}

var _ providers.Interface = (*Provider)(nil)

func unsupported(what string) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	return diags.Append(fmt.Errorf("the conn3x provider does not support %s", what))
}

func (p *Provider) GetProviderSchema(context.Context) providers.GetProviderSchemaResponse {
	return providers.GetProviderSchemaResponse{
		Provider:      providers.Schema{Block: emptyBlock()},
		ResourceTypes: map[string]providers.Schema{},
		DataSources:   map[string]providers.Schema{},
	}
}

func (p *Provider) ValidateProviderConfig(_ context.Context, req providers.ValidateProviderConfigRequest) providers.ValidateProviderConfigResponse {
	return providers.ValidateProviderConfigResponse{PreparedConfig: req.Config}
}

func (p *Provider) ValidateResourceConfig(context.Context, providers.ValidateResourceConfigRequest) providers.ValidateResourceConfigResponse {
	return providers.ValidateResourceConfigResponse{}
}

func (p *Provider) ValidateDataResourceConfig(context.Context, providers.ValidateDataResourceConfigRequest) providers.ValidateDataResourceConfigResponse {
	return providers.ValidateDataResourceConfigResponse{Diagnostics: unsupported("data sources")}
}

func (p *Provider) ValidateEphemeralConfig(context.Context, providers.ValidateEphemeralConfigRequest) providers.ValidateEphemeralConfigResponse {
	return providers.ValidateEphemeralConfigResponse{Diagnostics: unsupported("ephemeral resources")}
}

func (p *Provider) MoveResourceState(context.Context, providers.MoveResourceStateRequest) providers.MoveResourceStateResponse {
	return providers.MoveResourceStateResponse{Diagnostics: unsupported("moving resource state")}
}

func (p *Provider) CallFunction(context.Context, providers.CallFunctionRequest) providers.CallFunctionResponse {
	return providers.CallFunctionResponse{Error: fmt.Errorf("the conn3x provider has no functions")}
}

func (p *Provider) ConfigureProvider(context.Context, providers.ConfigureProviderRequest) providers.ConfigureProviderResponse {
	return providers.ConfigureProviderResponse{}
}

func (p *Provider) Close(context.Context) error { return nil }

func (p *Provider) Stop(context.Context) error { return nil }

func (p *Provider) UpgradeResourceState(_ context.Context, req providers.UpgradeResourceStateRequest) providers.UpgradeResourceStateResponse {
	return providers.UpgradeResourceStateResponse{Diagnostics: unsupported("resource type " + req.TypeName)}
}

func (p *Provider) UpgradeResourceIdentity(context.Context, providers.UpgradeResourceIdentityRequest) providers.UpgradeResourceIdentityResponse {
	return providers.UpgradeResourceIdentityResponse{Diagnostics: unsupported("resource identity")}
}

func (p *Provider) ReadResource(_ context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return providers.ReadResourceResponse{Diagnostics: unsupported("resource type " + req.TypeName)}
}

func (p *Provider) PlanResourceChange(_ context.Context, req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return providers.PlanResourceChangeResponse{Diagnostics: unsupported("resource type " + req.TypeName)}
}

func (p *Provider) ApplyResourceChange(_ context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return providers.ApplyResourceChangeResponse{Diagnostics: unsupported("resource type " + req.TypeName)}
}

func (p *Provider) ImportResourceState(context.Context, providers.ImportResourceStateRequest) providers.ImportResourceStateResponse {
	return providers.ImportResourceStateResponse{Diagnostics: unsupported("import")}
}

func (p *Provider) ReadDataSource(context.Context, providers.ReadDataSourceRequest) providers.ReadDataSourceResponse {
	return providers.ReadDataSourceResponse{Diagnostics: unsupported("data sources")}
}

func (p *Provider) OpenEphemeralResource(context.Context, providers.OpenEphemeralResourceRequest) providers.OpenEphemeralResourceResponse {
	return providers.OpenEphemeralResourceResponse{Diagnostics: unsupported("ephemeral resources")}
}

func (p *Provider) RenewEphemeralResource(context.Context, providers.RenewEphemeralResourceRequest) providers.RenewEphemeralResourceResponse {
	return providers.RenewEphemeralResourceResponse{Diagnostics: unsupported("ephemeral resources")}
}

func (p *Provider) CloseEphemeralResource(context.Context, providers.CloseEphemeralResourceRequest) providers.CloseEphemeralResourceResponse {
	return providers.CloseEphemeralResourceResponse{Diagnostics: unsupported("ephemeral resources")}
}

func (p *Provider) GetFunctions(context.Context) providers.GetFunctionsResponse {
	return providers.GetFunctionsResponse{}
}
