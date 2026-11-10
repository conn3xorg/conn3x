// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
)

// decodeIdempotent reads a run block's idempotent argument, which plans
// again after the apply and fails the run on any change.
func decodeIdempotent(content *hcl.BodyContent, r *TestRun) hcl.Diagnostics {
	var diags hcl.Diagnostics
	if attr, exists := content.Attributes["idempotent"]; exists {
		valDiags := gohcl.DecodeExpression(attr.Expr, nil, &r.Idempotent)
		diags = append(diags, valDiags...)
		if r.Idempotent && r.Command != ApplyTestCommand {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid \"idempotent\" argument",
				Detail:   "idempotent plans again after an apply, so it needs command = apply.",
				Subject:  attr.Expr.Range().Ptr(),
			})
		}
		if r.Idempotent && len(r.Options.Replace) > 0 {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid \"idempotent\" argument",
				Detail:   "plan_options sets replace, which plans a change every time, so the second plan could never be empty.",
				Subject:  attr.Expr.Range().Ptr(),
			})
		}
	}
	return diags
}
