// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
)

// Every host resource has a revision that changes exactly when Conn3x
// changes something on the host. Handlers watch it, so putting back a hand
// edit fires them too, even though the result matches the last apply.

func revisionAttr() *configschema.Attribute {
	return &configschema.Attribute{
		Type: cty.String, Computed: true,
		Description: "Changes each time Conn3x changes this on the host. Handlers watch it.",
	}
}

// planRevision keeps the prior revision when the plan changes nothing else,
// and leaves it unknown when the host is about to change.
func planRevision(prior, planned cty.Value) cty.Value {
	if planned.IsNull() || !planned.Type().IsObjectType() || !planned.Type().HasAttribute("revision") {
		return planned
	}
	vals := planned.AsValueMap()
	if prior.IsNull() {
		vals["revision"] = cty.UnknownVal(cty.String)
		return cty.ObjectVal(vals)
	}
	vals["revision"] = prior.GetAttr("revision")
	if same := cty.ObjectVal(vals); same.RawEquals(prior) {
		return same
	}
	vals["revision"] = cty.UnknownVal(cty.String)
	return cty.ObjectVal(vals)
}

// applyRevision gives an applied change a new revision.
func applyRevision(planned, state cty.Value) cty.Value {
	if state.IsNull() || !state.Type().HasAttribute("revision") || planned.IsNull() || planned.GetAttr("revision").IsKnown() {
		return state
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	vals := state.AsValueMap()
	vals["revision"] = cty.StringVal(hex.EncodeToString(b))
	return cty.ObjectVal(vals)
}
