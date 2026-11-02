// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"slices"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// planSyncedFold is planSynced for Windows names, which ignore case: a key
// that changes only in case is an update, not a delete and a new object.
func planSyncedFold(req providers.PlanResourceChangeRequest, kind string, keys, settings []string) providers.PlanResourceChangeResponse {
	resp := planSynced(req, kind, keys, settings)
	if req.PriorState.IsNull() || resp.PlannedState.IsNull() {
		return resp
	}
	var replace []cty.Path
	for _, p := range resp.RequiresReplace {
		if step, ok := p[0].(cty.GetAttrStep); ok && len(p) == 1 && slices.Contains(keys, step.Name) {
			a, b := req.PriorState.GetAttr(step.Name), resp.PlannedState.GetAttr(step.Name)
			if known(a) && known(b) && strings.EqualFold(a.AsString(), b.AsString()) {
				continue
			}
		}
		replace = append(replace, p)
	}
	resp.RequiresReplace = replace
	return resp
}
