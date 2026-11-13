// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/secrets"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// conn3x_secrets reads a SOPS file. It's an ephemeral resource, not a data
// source, so its values are never written to state or plan files, and
// OpenTofu refuses them anywhere that would keep them.

const secretsType = "conn3x_secrets"

func secretsSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "The values of a SOPS file encrypted with age, read on the machine running Conn3x and kept out of state and plan files.",
		Attributes: map[string]*configschema.Attribute{
			"file":   {Type: cty.String, Required: true, Description: "The SOPS file, YAML or JSON. A relative path is relative to where conn3x runs; start it with path.module to make it relative to the configuration."},
			"values": {Type: cty.Map(cty.String), Computed: true, Sensitive: true, Description: "The decrypted values, by key: top-level keys as written, nested ones joined with dots, such as db.password, and list items by index, such as hosts.0."},
		},
	}}
}

func validateSecrets(req providers.ValidateEphemeralConfigRequest) providers.ValidateEphemeralConfigResponse {
	if req.TypeName != secretsType {
		return providers.ValidateEphemeralConfigResponse{Diagnostics: unsupported("ephemeral resource " + req.TypeName)}
	}
	return providers.ValidateEphemeralConfigResponse{}
}

func openSecrets(req providers.OpenEphemeralResourceRequest) providers.OpenEphemeralResourceResponse {
	var resp providers.OpenEphemeralResourceResponse
	if req.TypeName != secretsType {
		resp.Diagnostics = unsupported("ephemeral resource " + req.TypeName)
		return resp
	}
	file := req.Config.GetAttr("file")
	if !file.IsKnown() {
		resp.Result = cty.ObjectVal(map[string]cty.Value{"file": file, "values": cty.UnknownVal(cty.Map(cty.String))})
		return resp
	}
	got, err := secrets.ReadFile(file.AsString())
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.AttributeValue(tfdiags.Error, "Can't read the secrets file", err.Error(), cty.GetAttrPath("file")))
		return resp
	}
	values := cty.MapValEmpty(cty.String)
	if len(got) > 0 {
		m := make(map[string]cty.Value, len(got))
		for k, v := range got {
			m[k] = cty.StringVal(v)
		}
		values = cty.MapVal(m)
	}
	resp.Result = cty.ObjectVal(map[string]cty.Value{"file": file, "values": values})
	return resp
}
