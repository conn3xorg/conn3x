// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// A step's lifecycle block is decoded by upstream's own resource decoder,
// on a synthetic resource block that holds only the lifecycle block, so
// steps get every lifecycle behaviour, check and error message a resource
// has. Conn3x only filters what a step can't use and rewrites names first.

// cbdModules are the modules whose replacement is always a different object
// on the host, so adding the new one before removing the old is safe.
var cbdModules = map[string]bool{
	"authorized_key":         true,
	"firewalld":              true,
	"ufw":                    true,
	"cron":                   true,
	"timer":                  true,
	"repository":             true,
	"windows_firewall_rule":  true,
	"windows_scheduled_task": true,
	"windows_iis_site":       true,
	"windows_iis_app_pool":   true,
}

// stepRejectedLifecycle are the lifecycle arguments a step refuses, and why.
var stepRejectedLifecycle = map[string]string{
	"enabled": "A step already repeats over its hosts with for_each, and OpenTofu doesn't allow enabled beside for_each. To run a step on fewer hosts, filter hosts; to run it nowhere, give the step an empty for_each.",
	"destroy": "A step says what removal does with its module's on_remove argument. Set on_remove = \"forget\" to leave the object on the host.",
}

// templateLowered maps a template step's arguments to the conn3x_file
// arguments they become, so ignore_changes can name what the user wrote.
var templateLowered = map[string]string{"source": "content", "vars": "content", "destination": "path"}

func stepLifecycle(r *Resource, module *hclsyntax.Block, blocks hclsyntax.Blocks, looping bool) hcl.Diagnostics {
	var diags hcl.Diagnostics
	for _, lc := range blocks {
		for name, why := range stepRejectedLifecycle {
			if a, ok := lc.Body.Attributes[name]; ok {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  fmt.Sprintf("Unsupported lifecycle argument in step: %s", name),
					Detail:   why,
					Subject:  a.NameRange.Ptr(),
				})
			}
		}
		if a, ok := lc.Body.Attributes["replace_triggered_by"]; ok && looping {
			// Upstream allows only each.key here, which in a looping step is
			// the instance key "host/item", not the host the step means.
			for _, tr := range a.Expr.Variables() {
				if root := tr.RootName(); root == "each" || root == "item" {
					diags = append(diags, &hcl.Diagnostic{
						Severity: hcl.DiagError,
						Summary:  "each or item in replace_triggered_by of a looping step",
						Detail:   "In a step with for_each, replace_triggered_by can name whole resources, such as conn3x_file.web__conf, but not one instance by each or item.",
						Subject:  tr.SourceRange().Ptr(),
					})
				}
			}
		}
		if module.Type == "template" {
			renameTemplateIgnores(lc, r)
		}
		diags = append(diags, loopRefs(lc.Body.Attributes, lc.Body.Blocks, looping)...)
	}
	if diags.HasErrors() {
		return diags
	}

	first := blocks[0]
	synthetic := &hclsyntax.Block{
		Type:            "resource",
		Labels:          []string{r.Type, r.Name},
		Body:            &hclsyntax.Body{Blocks: blocks, SrcRange: first.Range(), EndRange: first.CloseBraceRange},
		TypeRange:       first.TypeRange,
		LabelRanges:     []hcl.Range{r.TypeRange, r.DeclRange},
		OpenBraceRange:  first.OpenBraceRange,
		CloseBraceRange: first.CloseBraceRange,
	}
	decoded, decodeDiags := decodeResourceBlock(synthetic.AsHCLBlock(), false)
	diags = append(diags, decodeDiags...)
	if decoded == nil || decodeDiags.HasErrors() {
		return diags
	}
	m := decoded.Managed
	r.Managed.CreateBeforeDestroy, r.Managed.CreateBeforeDestroySet = m.CreateBeforeDestroy, m.CreateBeforeDestroySet
	r.Managed.PreventDestroy = m.PreventDestroy
	r.Managed.IgnoreChanges, r.Managed.IgnoreAllChanges = m.IgnoreChanges, m.IgnoreAllChanges
	r.TriggersReplacement = decoded.TriggersReplacement
	r.Preconditions, r.Postconditions = decoded.Preconditions, decoded.Postconditions

	if m.CreateBeforeDestroy && !cbdModules[module.Type] {
		var rng *hcl.Range
		for _, lc := range blocks {
			if a, ok := lc.Body.Attributes["create_before_destroy"]; ok {
				rng = a.SrcRange.Ptr()
			}
		}
		allowed := make([]string, 0, len(cbdModules))
		for name := range cbdModules {
			allowed = append(allowed, name)
		}
		sort.Strings(allowed)
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("create_before_destroy isn't available on a %s step", module.Type),
			Detail: fmt.Sprintf("Replacing a %s step can land on the same object on the host, and the old object's removal would then delete what was just created, so create_before_destroy has nothing to keep. It works on steps whose replacement is always a different object: %s.",
				module.Type, strings.Join(allowed, ", ")),
			Subject: rng,
		})
	}
	return diags
}

// renameTemplateIgnores rewrites ignore_changes = [source, vars, destination]
// to the conn3x_file arguments a template step lowers to. Renaming in place
// is safe to repeat: the new names aren't renamed again.
func renameTemplateIgnores(lc *hclsyntax.Block, r *Resource) {
	a, ok := lc.Body.Attributes["ignore_changes"]
	if !ok {
		return
	}
	list, ok := a.Expr.(*hclsyntax.TupleConsExpr)
	if !ok {
		return // ignore_changes = all
	}
	content := "content"
	if body, ok := r.Config.(*hclsyntax.Body); ok && body.Attributes["content_wo"] != nil {
		content = "content_wo" // upstream then explains write-only arguments can't be ignored
	}
	// shortcut: only bare names are renamed, not the legacy quoted form; upstream reports a quoted "source" as unknown.
	for _, e := range list.Exprs {
		t, ok := e.(*hclsyntax.ScopeTraversalExpr)
		if !ok || len(t.Traversal) == 0 {
			continue
		}
		root, ok := t.Traversal[0].(hcl.TraverseRoot)
		if !ok {
			continue
		}
		to, ok := templateLowered[root.Name]
		if !ok {
			continue
		}
		if to == "content" {
			to = content
		}
		root.Name = to
		t.Traversal[0] = root
	}
}
