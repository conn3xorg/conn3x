// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/importid"
	"github.com/opentofu/opentofu/internal/providers"
)

// import_id lets a root import block adopt a step inside a module, such as
// an official circuit, where a step's own import can't reach:
//
//	import {
//	  for_each = local.hosts
//	  to       = module.web.conn3x_file.nginx__conf[each.key]
//	  id       = provider::conn3x::import_id(each.key, { host = each.value, user = "root" }, { path = "/etc/nginx/nginx.conf" })
//	}
var functions = map[string]providers.FunctionSpec{
	"import_id": {
		Parameters: []providers.FunctionParameterSpec{
			{Name: "key", Type: cty.String, Description: "The host's key in the circuit's hosts, such as web1."},
			{Name: "ssh", Type: cty.DynamicPseudoType, Description: "The circuit's ssh settings, with the host's address as host."},
			{Name: "args", Type: cty.DynamicPseudoType, Description: "The step's module arguments as the circuit sets them; content, content_wo and validate are left out."},
		},
		Return:  cty.String,
		Summary: "The import ID for one host of a step, as a step's import = true would write it.",
	},
}

func (p *Provider) GetFunctions(context.Context) providers.GetFunctionsResponse {
	return providers.GetFunctionsResponse{Functions: functions}
}

func (p *Provider) CallFunction(_ context.Context, req providers.CallFunctionRequest) providers.CallFunctionResponse {
	if req.Name != "import_id" {
		return providers.CallFunctionResponse{Error: fmt.Errorf("the conn3x provider has no function %q", req.Name)}
	}
	if len(req.Arguments) != 3 {
		return providers.CallFunctionResponse{Error: fmt.Errorf("import_id takes 3 arguments, key, ssh and args, not %d", len(req.Arguments))}
	}
	key := req.Arguments[0]
	if key.IsNull() {
		return providers.CallFunctionResponse{Error: &providers.CallFunctionArgumentError{Text: "key can't be null", FunctionArgument: 0}}
	}
	id, err := importid.Build(key.AsString(), req.Arguments[1], req.Arguments[2])
	if err != nil {
		return providers.CallFunctionResponse{Error: fmt.Errorf("import_id: %w", err)}
	}
	return providers.CallFunctionResponse{Result: cty.StringVal(id)}
}
