// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package tofu

import (
	"context"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/addrs"
	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/lang/marks"
	"github.com/opentofu/opentofu/internal/plans"
	"github.com/opentofu/opentofu/internal/plugins"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/states"
)

func TestConn3xFileSha256SensitiveWithContent(t *testing.T) {
	m := testModuleInline(t, map[string]string{
		"main.tf": `
variable "secret" {
  type      = string
  sensitive = true
}

resource "conn3x_file" "secret" {
  content = var.secret
}

resource "conn3x_file" "plain" {
  content = "hello"
}
`,
	})
	p := new(MockProvider)
	p.GetProviderSchemaResponse = getProviderSchemaResponseFromProviderSchema(&ProviderSchema{
		ResourceTypes: map[string]*configschema.Block{
			"conn3x_file": {
				Attributes: map[string]*configschema.Attribute{
					"content": {Type: cty.String, Optional: true},
					"sha256":  {Type: cty.String, Computed: true},
				},
			},
		},
	})
	p.PlanResourceChangeFn = func(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
		vals := req.ProposedNewState.AsValueMap()
		vals["sha256"] = cty.StringVal("hash of " + vals["content"].AsString())
		return providers.PlanResourceChangeResponse{PlannedState: cty.ObjectVal(vals)}
	}
	ctx := testContext2(t, &ContextOpts{
		Plugins: plugins.NewLibrary(map[addrs.Provider]providers.Factory{
			addrs.NewBuiltInProvider("conn3x"): testProviderFuncFixed(p),
		}, nil),
	})

	opts := SimplePlanOpts(plans.NormalMode, InputValues{
		"secret": &InputValue{Value: cty.StringVal("hunter2"), SourceType: ValueFromCaller},
	})
	plan, diags := ctx.Plan(context.Background(), m, states.NewState(), opts)
	assertNoErrors(t, diags)

	want := map[string]bool{"conn3x_file.secret": true, "conn3x_file.plain": false}
	for _, rc := range plan.Changes.Resources {
		sensitive := false
		for _, pvm := range rc.AfterValMarks {
			if pvm.Path.Equals(cty.GetAttrPath("sha256")) && pvm.Marks.Has(marks.Sensitive) {
				sensitive = true
			}
		}
		if sensitive != want[rc.Addr.String()] {
			t.Errorf("%s: sha256 sensitive = %v, want %v", rc.Addr, sensitive, want[rc.Addr.String()])
		}
	}
}
