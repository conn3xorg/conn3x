// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package tofu

import (
	"context"

	"github.com/hashicorp/hcl/v2"

	"github.com/opentofu/opentofu/internal/addrs"
	"github.com/opentofu/opentofu/internal/instances"
)

// conn3xRepetitionData returns each.key and each.value for addr from the
// expansion its resource registered, rather than evaluating for_each again.
// A circuit step's for_each holds every host, so evaluating it once per
// instance made a plan O(instances x hosts): 37% of plan CPU at 500 hosts.
// It falls back to evaluating when the expander has no such instance.
func conn3xRepetitionData(ctx context.Context, evalCtx EvalContext, forEach hcl.Expression, addr addrs.AbsResourceInstance) (data instances.RepetitionData) {
	if forEach != nil {
		ok := func() (ok bool) {
			// The expander panics on an address it never registered.
			defer func() { ok = recover() == nil && ok }()
			data = evalCtx.InstanceExpander().GetResourceInstanceRepetitionData(addr)
			return true
		}()
		if ok {
			return data
		}
	}
	vals, _ := evaluateForEachExpression(ctx, forEach, evalCtx, addr)
	return EvalDataForInstanceKey(addr.Resource.Key, vals)
}
