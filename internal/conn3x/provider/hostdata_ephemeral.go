// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/hostdata"
	"github.com/opentofu/opentofu/internal/conn3x/secrets"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// conn3x_hostdata reads the hierarchy provider::conn3x::hostdata reads, with
// SOPS layers decrypted. It's ephemeral, so the values, secrets included,
// never reach plan or state.
const hostdataType = "conn3x_hostdata"

func hostdataSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Layered host data, as provider::conn3x::hostdata reads it, with layers encrypted with SOPS and age decrypted on the machine running Conn3x. Ephemeral: the values are kept out of plan and state, so they go into write-only arguments such as password_wo.",
		Attributes: map[string]*configschema.Attribute{
			"dir":    {Type: cty.String, Required: true, Description: "The data directory, with hierarchy.yaml at its top, as for hostdata."},
			"vars":   {Type: cty.DynamicPseudoType, Optional: true, Description: "What fills the layers' {placeholders}, as for hostdata: each a string or a list of strings."},
			"values": {Type: cty.DynamicPseudoType, Computed: true, Sensitive: true, Description: "The merged values, by key. A value from an encrypted layer is a string, and its nested keys are joined with dots, such as db.password, as conn3x_secrets gives them."},
			"from":   {Type: cty.Map(cty.String), Computed: true, Description: "For each key, the layer file it came from."},
		},
	}}
}

func validateHostdataEphemeral(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if v := cfg.GetAttr("vars"); v.IsWhollyKnown() {
		if _, why := hostDataVars(v); why != "" {
			diags = diags.Append(attrError("vars", why))
		}
	}
	return diags
}

func openHostdata(req providers.OpenEphemeralResourceRequest) providers.OpenEphemeralResourceResponse {
	var resp providers.OpenEphemeralResourceResponse
	dir, varsVal := req.Config.GetAttr("dir"), req.Config.GetAttr("vars")
	if !dir.IsKnown() || !varsVal.IsWhollyKnown() {
		resp.Result = cty.ObjectVal(map[string]cty.Value{"dir": dir, "vars": varsVal, "values": cty.DynamicVal, "from": cty.UnknownVal(cty.Map(cty.String))})
		return resp
	}
	vars, why := hostDataVars(varsVal)
	if why != "" {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("vars", why))
		return resp
	}
	res, err := hostdata.LoadDecrypting(dir.AsString(), vars, secrets.ReadFile)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.AttributeValue(tfdiags.Error, "Can't read the host data", err.Error(), cty.GetAttrPath("dir")))
		return resp
	}
	values, from := hostDataResult(res)
	resp.Result = cty.ObjectVal(map[string]cty.Value{"dir": dir, "vars": varsVal, "values": values, "from": from})
	return resp
}
