// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package tofu

import (
	"context"
	"testing"

	"github.com/hashicorp/hcl/v2/hcltest"
	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/addrs"
	"github.com/opentofu/opentofu/internal/instances"
)

func TestConn3xRepetitionData(t *testing.T) {
	res := addrs.Resource{Mode: addrs.ManagedResourceMode, Type: "conn3x_step", Name: "s"}
	inst := res.Instance(addrs.StringKey("web")).Absolute(addrs.RootModuleInstance)
	forEach := hcltest.MockExprLiteral(cty.MapVal(map[string]cty.Value{"web": cty.StringVal("evaluated")}))

	expander := instances.NewExpander()
	expander.SetResourceForEach(addrs.RootModuleInstance, res, map[string]cty.Value{"web": cty.StringVal("expanded")})
	got := conn3xRepetitionData(context.Background(), &MockEvalContext{InstanceExpanderExpander: expander}, forEach, inst)
	if !got.EachValue.RawEquals(cty.StringVal("expanded")) {
		t.Errorf("registered: each.value = %#v, want the expansion's", got.EachValue)
	}

	evalCtx := &MockEvalContext{InstanceExpanderExpander: instances.NewExpander(), EvaluateExprResult: cty.MapVal(map[string]cty.Value{"web": cty.StringVal("evaluated")})}
	got = conn3xRepetitionData(context.Background(), evalCtx, forEach, inst)
	if !got.EachValue.RawEquals(cty.StringVal("evaluated")) {
		t.Errorf("unregistered: each.value = %#v, want the evaluated for_each", got.EachValue)
	}
}
