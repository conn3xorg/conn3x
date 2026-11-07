// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package tofu

import (
	"slices"

	"github.com/opentofu/opentofu/internal/addrs"
	"github.com/opentofu/opentofu/internal/configs"
	"github.com/opentofu/opentofu/internal/dag"
)

// conn3xHostEdges narrows the apply graph's edges for the references a
// circuit's lowering generates, so each host runs its own chain of steps:
// host A's step 2 waits for host A's step 1, not for host B's. Everything
// else, including any reference the user wrote, keeps OpenTofu's edges.
func conn3xHostEdges(current dag.Vertex, ref *addrs.Reference, vertices []dag.Vertex) []dag.Vertex {
	var cfg *configs.Resource
	var hosts []string
	expand := false
	switch n := current.(type) {
	case *NodeApplyableResourceInstance:
		cfg = n.Config
		if cfg != nil {
			hosts = configs.Conn3xStepHosts(cfg, n.Addr.Resource.Key)
		}
	case *nodeExpandApplyableResource:
		cfg, expand = n.Config, true
	default:
		return vertices
	}
	if !configs.Conn3xHostEdge(cfg, ref.SourceRange.ToHCL()) || (!expand && len(hosts) == 0) {
		return vertices
	}
	var out []dag.Vertex
	for _, v := range vertices {
		inst, ok := v.(*NodeApplyableResourceInstance)
		if !ok || inst.Config == nil {
			out = append(out, v) // expand and other nodes keep their edge
			continue
		}
		if !expand && slices.ContainsFunc(hosts, func(h string) bool {
			return configs.Conn3xStepOnHost(inst.Config, inst.Addr.Resource.Key, h)
		}) {
			out = append(out, v)
		}
	}
	return out
}
