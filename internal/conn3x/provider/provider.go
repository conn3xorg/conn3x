// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package provider is Conn3x's built-in provider. Its resources describe
// the state of hosts: files, packages, services and users.
package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// Provider implements providers.Interface in process.
type Provider struct{}

// resourceType is everything the provider needs to serve one resource type.
type resourceType struct {
	schema   func() providers.Schema
	validate func(cty.Value) tfdiags.Diagnostics
	plan     func(providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse
	read     func(context.Context, providers.ReadResourceRequest) providers.ReadResourceResponse
	apply    func(context.Context, providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse
	upgrade  func(providers.UpgradeResourceStateRequest) providers.UpgradeResourceStateResponse
}

var resourceTypes = map[string]resourceType{
	"conn3x_file":           {fileSchema, validateFile, planFile, readFile, applyFile, upgradeFile},
	"conn3x_package":        {packageSchema, validatePackage, planPackage, readPackage, applyPackage, upgradePackage},
	"conn3x_service":        {serviceSchema, validateService, planService, readService, applyService, upgradeService},
	"conn3x_user":           {userSchema, validateUser, planUser, readUser, applyUser, upgradeWith(userSchema)},
	"conn3x_service_action": {serviceActionSchema, validateServiceAction, planServiceAction, readServiceAction, applyServiceAction, upgradeWith(serviceActionSchema)},
	"conn3x_command":        {commandSchema, validateCommand, planCommand, readCommand, applyCommand, upgradeWith(commandSchema)},
	"conn3x_directory":      {directorySchema, validateDirectory, planDirectory, readDirectory, applyDirectory, upgradeWith(directorySchema)},
	"conn3x_link":           {linkSchema, validateLink, planLink, readLink, applyLink, upgradeWith(linkSchema)},
	"conn3x_line":           {lineKind.schema, lineKind.validate, lineKind.plan, lineKind.read, lineKind.apply, upgradeWith(lineKind.schema)},
	"conn3x_block":          {blockKind.schema, blockKind.validate, blockKind.plan, blockKind.read, blockKind.apply, upgradeWith(blockKind.schema)},
	"conn3x_authorized_key": {authorizedKeySchema, validateAuthorizedKey, planAuthorizedKey, readAuthorizedKey, applyAuthorizedKey, upgradeWith(authorizedKeySchema)},
	"conn3x_group":          {groupSchema, validateGroup, planGroup, readGroup, applyGroup, upgradeWith(groupSchema)},
}

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
		ResourceTypes: resourceSchemas(),
		DataSources:   map[string]providers.Schema{},
	}
}

func (p *Provider) ValidateProviderConfig(_ context.Context, req providers.ValidateProviderConfigRequest) providers.ValidateProviderConfigResponse {
	return providers.ValidateProviderConfigResponse{PreparedConfig: req.Config}
}

func (p *Provider) ValidateResourceConfig(_ context.Context, req providers.ValidateResourceConfigRequest) providers.ValidateResourceConfigResponse {
	if rt, ok := resourceTypes[req.TypeName]; ok {
		diags := rt.validate(req.Config)
		diags = diags.Append(validateSSH(req.Config))
		return providers.ValidateResourceConfigResponse{Diagnostics: diags}
	}
	return providers.ValidateResourceConfigResponse{Diagnostics: unsupported("resource type " + req.TypeName)}
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
	if rt, ok := resourceTypes[req.TypeName]; ok {
		return rt.upgrade(req)
	}
	return providers.UpgradeResourceStateResponse{Diagnostics: unsupported("resource type " + req.TypeName)}
}

func (p *Provider) UpgradeResourceIdentity(context.Context, providers.UpgradeResourceIdentityRequest) providers.UpgradeResourceIdentityResponse {
	return providers.UpgradeResourceIdentityResponse{Diagnostics: unsupported("resource identity")}
}

func (p *Provider) ReadResource(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	if rt, ok := resourceTypes[req.TypeName]; ok {
		return rt.read(ctx, req)
	}
	return providers.ReadResourceResponse{Diagnostics: unsupported("resource type " + req.TypeName)}
}

func (p *Provider) PlanResourceChange(_ context.Context, req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	if rt, ok := resourceTypes[req.TypeName]; ok {
		return rt.plan(req)
	}
	return providers.PlanResourceChangeResponse{Diagnostics: unsupported("resource type " + req.TypeName)}
}

func (p *Provider) ApplyResourceChange(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	if rt, ok := resourceTypes[req.TypeName]; ok {
		return rt.apply(ctx, req)
	}
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

func resourceSchemas() map[string]providers.Schema {
	out := make(map[string]providers.Schema, len(resourceTypes))
	for name, rt := range resourceTypes {
		out[name] = rt.schema()
	}
	return out
}
