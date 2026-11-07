// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/addrs"
)

// Conn3xHostEdge reports whether ref, made by r at rng, is one a circuit's
// lowering generated (the chain to the step before, or a handler's
// depends_on and triggers). Those only need the same host's instances.
func Conn3xHostEdge(r *Resource, rng hcl.Range) bool {
	if r == nil || !strings.Contains(r.Name, "__") || !strings.HasPrefix(r.Type, "conn3x_") {
		return false
	}
	return rng.Filename == r.DeclRange.Filename && rng.Start == r.DeclRange.Start && rng.End == r.DeclRange.End
}

// Conn3xStepOnHost reports whether instance key of circuit resource r runs
// on host. A step with for_each is keyed "<host>/<item key>".
func Conn3xStepOnHost(r *Resource, key addrs.InstanceKey, host string) bool {
	k, ok := key.(addrs.StringKey)
	if !ok {
		return true // not a circuit instance: keep the edge
	}
	if _, looping := r.ForEach.(*hostItemProduct); looping {
		return strings.HasPrefix(string(k), host+"/")
	}
	return string(k) == host
}

// Conn3xStepHosts lists the hosts instance key of r may belong to. A host
// key can itself hold "/", so a looping step's key may name several; an
// extra candidate only adds a wait, never drops one.
func Conn3xStepHosts(r *Resource, key addrs.InstanceKey) []string {
	k, ok := key.(addrs.StringKey)
	if !ok {
		return nil
	}
	if _, looping := r.ForEach.(*hostItemProduct); !looping {
		return []string{string(k)}
	}
	var hosts []string
	for i := range len(k) {
		if k[i] == '/' {
			hosts = append(hosts, string(k[:i]))
		}
	}
	return hosts
}

// circuitStrategy reads a circuit's strategy: "lockstep" (the default) or
// "per_host". It reports whether each host runs its own chain of steps.
func circuitStrategy(attr *hcl.Attribute) (bool, hcl.Diagnostics) {
	if attr == nil {
		return false, nil
	}
	v, diags := attr.Expr.Value(nil)
	if !diags.HasErrors() && v.Type() == cty.String && v.IsKnown() && !v.IsNull() {
		switch v.AsString() {
		case "lockstep":
			return false, nil
		case "per_host":
			return true, nil
		}
	}
	return false, hcl.Diagnostics{{
		Severity: hcl.DiagError,
		Summary:  "Invalid circuit strategy",
		Detail:   `strategy must be "lockstep", where each step waits for the step before it on every host, or "per_host", where it waits only on its own host.`,
		Subject:  attr.Expr.Range().Ptr(),
	}}
}

// chainRange is the range a step or handler gives the edges the lowering
// makes. Conn3xHostEdge narrows only those whose range is the block's
// DefRange, so "lockstep" uses the type keyword's range and keeps
// OpenTofu's whole-resource edges.
func chainRange(b *hcl.Block, perHost bool) hcl.Range {
	if perHost {
		return b.DefRange
	}
	return b.TypeRange
}

// chainAfter is what the step after r waits for. In lockstep that's r. Per
// host, a looping r may have no items on a host, and then nothing of r on
// that host would carry the wait for the steps before it: so the next step
// also waits for those, back to the last step that doesn't loop.
func chainAfter(chain []*Resource, r *Resource, perHost bool) []*Resource {
	if _, looping := r.ForEach.(*hostItemProduct); perHost && looping {
		return append(slices.Clip(chain), r)
	}
	return []*Resource{r}
}
