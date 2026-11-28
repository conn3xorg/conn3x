// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/opentofu/opentofu/internal/addrs"
)

// A step's only_if is a condition the plan may not know yet, such as the
// exit code of a probe that reads the host after earlier steps changed it:
//
//	probe "has_php" { command = "command -v php" }
//	step "build" {
//	  only_if = data.conn3x_command.web__has_php[each.key].exit_code != 0
//	  command { ... }
//	}
//
// when can't take one: it filters for_each, which has to be known at plan.
// only_if goes to the step's resource as an argument instead, and the
// provider decides at apply whether the step runs (see only_if.go in the
// provider).

// stepOnlyIf checks a step's only_if: each and item mean in it what they
// mean in the module's arguments, and network device steps don't take it.
func stepOnlyIf(cond *hclsyntax.Attribute, module *hclsyntax.Block, resourceType string, looping bool) hcl.Diagnostics {
	for _, kind := range []string{"eos", "junos", "vyos", "ios"} {
		if strings.HasPrefix(resourceType, "conn3x_"+kind+"_") {
			return hcl.Diagnostics{{
				Severity: hcl.DiagError,
				Summary:  "only_if on a network device step",
				Detail:   fmt.Sprintf("A %s step stages lines that the circuit commits once per device, and that commit can't leave out a step decided at apply. Use when, which the plan decides.", module.Type),
				Subject:  cond.SrcRange.Ptr(),
			}}
		}
	}
	return loopRefs(hclsyntax.Attributes{"only_if": cond}, nil, looping)
}

// probeSchema is what a probe block takes: the command it runs.
var probeSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "command", Required: true}},
}

// lowerProbe lowers a circuit's probe to a conn3x_command data source,
// read on every host. It depends on every step declared before it, so
// when one of them has changes pending the read waits for the apply,
// after them, as an Ansible task with register runs after the tasks above
// it. Listing them all matters: a data source's depends_on isn't
// transitive, so naming only the last step would let a change two steps
// back be read at plan, stale. A probe with no steps before it reads at
// plan.
func lowerProbe(circuit string, probe *hcl.Block, hosts hcl.Expression, sshAttrs hclsyntax.Attributes, sshRange hcl.Range, earlier []*Resource, perHost bool) (*Resource, hcl.Diagnostics) {
	body, ok := probe.Body.(*hclsyntax.Body)
	if !ok {
		return nil, hcl.Diagnostics{nativeSyntaxRequired(probe.DefRange)}
	}
	if _, diags := probe.Body.Content(probeSchema); diags.HasErrors() {
		for _, d := range diags {
			if d.Summary == "Unsupported argument" || d.Summary == "Unsupported block type" {
				d.Detail = "A probe takes only command: the circuit's ssh block says how it reaches each host, and it reads every host in hosts."
			}
		}
		return nil, diags
	}
	cmd := body.Attributes["command"]
	if diags := loopRefs(hclsyntax.Attributes{"command": cmd}, nil, false); diags.HasErrors() {
		return nil, diags
	}
	r := &Resource{
		Mode: addrs.DataResourceMode,
		Type: "conn3x_command",
		Name: circuit + "__" + probe.Labels[0],
		Config: &hclsyntax.Body{
			Attributes: hclsyntax.Attributes{"command": cmd},
			Blocks:     hclsyntax.Blocks{sshBlockFor(sshAttrs, sshRange, []string{"value"})},
			SrcRange:   body.SrcRange,
			EndRange:   body.EndRange,
		},
		ForEach:   hosts,
		DeclRange: probe.DefRange,
		TypeRange: probe.TypeRange,
	}
	rng := chainRange(probe, perHost) // per host, Conn3xHostEdge keeps each edge to its host
	for _, step := range earlier {
		rng := rng
		if stepOnce(step.ForEach) {
			rng = probe.TypeRange // a run_once step's one instance is on another host
		}
		r.DependsOn = append(r.DependsOn, hcl.Traversal{
			hcl.TraverseRoot{Name: step.Type, SrcRange: rng},
			hcl.TraverseAttr{Name: step.Name, SrcRange: rng},
		})
	}
	return r, nil
}
