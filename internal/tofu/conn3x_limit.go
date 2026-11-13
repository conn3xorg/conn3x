// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package tofu

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/addrs"
	"github.com/opentofu/opentofu/internal/configs"
	"github.com/opentofu/opentofu/internal/conn3x/hostpattern"
	"github.com/opentofu/opentofu/internal/instances"
	"github.com/opentofu/opentofu/internal/plans"
	"github.com/opentofu/opentofu/internal/states"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// -limit, like Ansible's --limit, runs every circuit on some hosts only.
// It targets every circuit resource with a conn3xHostTarget, which
// contains only the instances on matching hosts, so OpenTofu's own
// targeting plans those instances, the rest of the configuration only where
// a step depends on it, and leaves the other hosts' steps in state as they
// are.

// Conn3xCLILimit is the -limit given to plan, apply or refresh. The conn3x
// command sets it (see cmd/conn3x/conn3x_limit.go); PlanOpts.Limit wins.
var Conn3xCLILimit *hostpattern.Pattern

// Conn3xCLILimitCircuit, when set, narrows Conn3xCLILimit to one root
// module circuit's steps, so a batched apply rolls out one circuit at a
// time on hosts that other circuits share.
var Conn3xCLILimitCircuit string

// conn3xHostTarget targets the instances of a circuit resource on the hosts
// a -limit matches. It embeds the resource's address, which makes it
// Targetable and gives it the address's String, so a saved plan records
// the whole resource.
type conn3xHostTarget struct {
	addrs.ConfigResource
	config *configs.Resource
	limit  *hostpattern.Pattern
	hosts  *conn3xLimitHosts
}

// conn3xLimitHosts holds the plan walk's instance expander, from which a
// looping instance's host is read: its key can't say, since a host name
// may hold the "/" that joins host and item.
type conn3xLimitHosts struct {
	expander *instances.Expander
}

func (t conn3xHostTarget) TargetContains(other addrs.Targetable) bool {
	inst, ok := other.(addrs.AbsResourceInstance)
	if !ok || !t.ConfigResource.TargetContains(inst) {
		return t.ConfigResource.TargetContains(other)
	}
	if _, ok := inst.Resource.Key.(addrs.StringKey); !ok {
		return true
	}
	hosts := configs.Conn3xStepHosts(t.config, inst.Resource.Key)
	if h, ok := t.hosts.of(inst); ok {
		hosts = []string{h}
	}
	// shortcut: an orphan or deposed looping instance whose host name holds
	// "/" is planned if any reading of its key matches.
	return slices.ContainsFunc(hosts, t.limit.Match)
}

// of reads inst's host from its each.value.host_key, once the plan walk
// has expanded inst.
func (h *conn3xLimitHosts) of(inst addrs.AbsResourceInstance) (string, bool) {
	if h.expander == nil || !h.expander.AllInstances().HasResourceInstance(inst) {
		return "", false
	}
	v := h.expander.GetResourceInstanceRepetitionData(inst).EachValue
	if v == cty.NilVal || !v.IsKnown() || v.IsNull() || !v.Type().IsObjectType() || !v.Type().HasAttribute("host_key") {
		return "", false
	}
	if k := v.GetAttr("host_key"); k.Type() == cty.String && k.IsKnown() && !k.IsNull() {
		return k.AsString(), true
	}
	return "", false
}

// conn3xLimitTargets checks a -limit and, unless -target or -exclude
// already narrow the plan, targets every circuit resource in config on the
// matching hosts.
func conn3xLimitTargets(config *configs.Config, state *states.State, opts *PlanOpts) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if opts.Limit == nil {
		opts.Limit = Conn3xCLILimit
	}
	if opts.Limit == nil {
		return diags
	}
	if opts.Mode == plans.DestroyMode {
		return diags.Append(tfdiags.Sourceless(tfdiags.Error, "-limit can't be used with -destroy",
			"A destroy with -limit would remove only some hosts' steps. To take a circuit off some hosts, remove them from its hosts and apply."))
	}
	if len(opts.Targets) > 0 || len(opts.Excludes) > 0 {
		if !opts.conn3xLimitTargeted {
			return diags.Append(tfdiags.Sourceless(tfdiags.Error, "-limit can't be used with -target or -exclude",
				"-limit chooses circuit steps by host, and -target and -exclude choose resources. Use one of them."))
		}
		opts.Targets = nil // these options planned before: target again
	}
	diags = diags.Append(tfdiags.Sourceless(tfdiags.Warning, "Limited to some hosts",
		fmt.Sprintf("This plan runs circuit steps only on the hosts that match %q. Steps on every other host are left as they are, so the plan doesn't show what they would change. Under lockstep, a step waits only for the matching hosts' steps before it.", opts.Limit)))

	hosts := &conn3xLimitHosts{}
	inConfig := map[string]bool{}
	var targets []addrs.Targetable
	config.DeepEach(func(c *configs.Config) {
		for _, r := range c.Module.ManagedResources {
			if configs.Conn3xCircuitResource(r) {
				addr := r.Addr().InModule(c.Path)
				inConfig[addr.String()] = true
				if Conn3xCLILimitCircuit != "" && (!c.Path.IsRoot() || !strings.HasPrefix(r.Name, Conn3xCLILimitCircuit+"__")) {
					continue
				}
				// A rescue phase plans the rescues and nothing else.
				if (configs.Conn3xRescueHosts != nil) != (c.Path.IsRoot() && configs.Conn3xRescueResource(r)) {
					continue
				}
				targets = append(targets, conn3xHostTarget{ConfigResource: addr, config: r, limit: opts.Limit, hosts: hosts})
			}
		}
	})
	// A step taken out of the configuration isn't targeted, so it isn't
	// removed from any host until a plan without -limit.
	if state != nil {
		var removed []string
		for _, r := range state.AllResourceInstanceObjectAddrs() {
			cr := r.Instance.ConfigResource()
			if res := cr.Resource; res.Mode == addrs.ManagedResourceMode && strings.Contains(res.Name, "__") && strings.HasPrefix(res.Type, "conn3x_") && !inConfig[cr.String()] && !slices.Contains(removed, cr.String()) {
				removed = append(removed, cr.String())
			}
		}
		if len(removed) > 0 {
			slices.Sort(removed)
			diags = diags.Append(tfdiags.Sourceless(tfdiags.Warning, "Removed steps stay on their hosts",
				fmt.Sprintf("These steps are in state but no longer in the configuration, and -limit doesn't remove them from any host: %s. A plan without -limit does.", strings.Join(removed, ", "))))
		}
	}

	if len(targets) == 0 {
		return diags.Append(tfdiags.Sourceless(tfdiags.Error, "-limit needs a circuit",
			"-limit picks which hosts circuit steps run on, and this configuration has no circuit."))
	}
	slices.SortFunc(targets, func(a, b addrs.Targetable) int { return strings.Compare(a.String(), b.String()) })
	opts.Targets, opts.conn3xLimitTargeted = targets, true
	return diags
}

// conn3xWalk is walk, but first gives a -limit's targets the walk's
// instance expander, so they can read each instance's host.
func (c *Context) conn3xWalk(ctx context.Context, graph *Graph, operation walkOperation, targets []addrs.Targetable, opts *graphWalkOpts) (*ContextGraphWalker, tfdiags.Diagnostics) {
	walker := c.graphWalker(operation, opts)
	for _, t := range targets {
		if t, ok := t.(conn3xHostTarget); ok {
			t.hosts.expander = walker.InstanceExpander
		}
	}
	watchStop, watchWait := c.watchStop(walker)
	diags := graph.Walk(ctx, walker, opts.BackupStateForPanic)
	close(watchStop)
	<-watchWait
	return walker, diags
}

// conn3xLimitMoves replaces OpenTofu's advice to add -target, when the
// targets came from -limit, with advice that works.
func conn3xLimitMoves(opts *PlanOpts, diags tfdiags.Diagnostics) tfdiags.Diagnostics {
	if !opts.conn3xLimitTargeted || !diags.HasErrors() {
		return diags
	}
	return tfdiags.Diagnostics{}.Append(tfdiags.Sourceless(tfdiags.Error, "moved blocks need a plan without -limit",
		"This configuration has moved blocks for resources or hosts that -limit doesn't plan. Apply once without -limit, so the moves happen, then use -limit again."))
}

// conn3xLimitMatched warns when a -limit matched no host at all, since
// that usually means a typo rather than a plan you wanted.
func conn3xLimitMatched(opts *PlanOpts) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if opts.Limit != nil && !opts.Limit.Matched() {
		diags = diags.Append(tfdiags.Sourceless(tfdiags.Warning, "-limit matched no host",
			fmt.Sprintf("No circuit host matched %q, so this plan changes no circuit step. Host names are the keys of each circuit's hosts.", opts.Limit)))
	}
	return diags
}
