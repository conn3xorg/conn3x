// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"fmt"
	"sync"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// A step with for_each repeats over items on every host. It lowers to one
// resource instance per host and item, keyed "<host>/<item key>", whose
// each.value is an object:
//
//	{ host_key = <host name>, host = <hosts entry>, item_key = <key>, item = <value> }
//
// Inside the step, each.key and each.value still mean the host, and
// item.key and item.value mean the item; rewriteLoopRefs maps them onto
// that object.

// hostItemProduct is a looping step's for_each.
type hostItemProduct struct {
	hosts, items hcl.Expression
}

var _ hcl.Expression = (*hostItemProduct)(nil)

func (p *hostItemProduct) Value(ctx *hcl.EvalContext) (cty.Value, hcl.Diagnostics) {
	hosts, diags := p.hosts.Value(ctx)
	items, itemDiags := p.items.Value(ctx)
	diags = append(diags, itemDiags...)
	if diags.HasErrors() {
		return cty.DynamicVal, diags
	}
	if !hosts.IsKnown() || !items.IsKnown() {
		return cty.DynamicVal, diags
	}
	pairs, err := itemPairs(items)
	if err != nil {
		rng := p.items.Range()
		return cty.DynamicVal, append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid for_each in step",
			Detail:   err.Error(),
			Subject:  &rng,
		})
	}
	if pairs == nil {
		return cty.DynamicVal, diags
	}
	out := map[string]cty.Value{}
	for it := hosts.ElementIterator(); it.Next(); {
		hk, hv := it.Element()
		for _, item := range pairs {
			out[hk.AsString()+"/"+item.key] = cty.ObjectVal(map[string]cty.Value{
				"host_key": hk, "host": hv, "item_key": cty.StringVal(item.key), "item": item.value,
			})
		}
	}
	if len(out) == 0 {
		return cty.EmptyObjectVal, diags
	}
	return cty.ObjectVal(out), diags
}

type itemPair struct {
	key   string
	value cty.Value
}

// itemPairs reads for_each: a map or object by key, or a list or set of
// strings with each string as its own key. It returns nil while any key is
// still unknown.
func itemPairs(items cty.Value) ([]itemPair, error) {
	ty := items.Type()
	if items.IsNull() {
		return nil, fmt.Errorf("for_each is null; give it a map, or a list or set of strings")
	}
	var pairs []itemPair
	switch {
	case ty.IsMapType() || ty.IsObjectType():
		for it := items.ElementIterator(); it.Next(); {
			k, v := it.Element()
			pairs = append(pairs, itemPair{k.AsString(), v})
		}
	case ty.IsListType() || ty.IsSetType() || ty.IsTupleType():
		seen := map[string]bool{}
		for it := items.ElementIterator(); it.Next(); {
			_, v := it.Element()
			if !v.IsKnown() {
				return nil, nil
			}
			if v.IsNull() || !v.Type().Equals(cty.String) {
				return nil, fmt.Errorf("a list or set in for_each must hold strings, which become the item keys; use a map for anything else")
			}
			if seen[v.AsString()] {
				return nil, fmt.Errorf("for_each lists %q twice; each item needs its own key", v.AsString())
			}
			seen[v.AsString()] = true
			pairs = append(pairs, itemPair{v.AsString(), v})
		}
	default:
		return nil, fmt.Errorf("for_each must be a map, or a list or set of strings, not %s", ty.FriendlyName())
	}
	return pairs, nil
}

func (p *hostItemProduct) Variables() []hcl.Traversal {
	return append(append([]hcl.Traversal{}, p.hosts.Variables()...), p.items.Variables()...)
}

func (p *hostItemProduct) Range() hcl.Range      { return p.items.Range() }
func (p *hostItemProduct) StartRange() hcl.Range { return p.items.StartRange() }

// hostInstances is a handler's trigger for a looping step: the revisions of
// the step's instances on the handler's host.
//
//	{ for k, v in STEP : k => v.revision if startswith(k, "${each.key}/") }
func hostInstances(step hclsyntax.Expression, rng hcl.Range) hclsyntax.Expression {
	local := func(name string) *hclsyntax.ScopeTraversalExpr {
		return &hclsyntax.ScopeTraversalExpr{Traversal: hcl.Traversal{hcl.TraverseRoot{Name: name, SrcRange: rng}}, SrcRange: rng}
	}
	prefix := &hclsyntax.TemplateExpr{
		Parts:    []hclsyntax.Expression{eachTraversal("key", rng), &hclsyntax.LiteralValueExpr{Val: cty.StringVal("/"), SrcRange: rng}},
		SrcRange: rng,
	}
	revision := &hclsyntax.ScopeTraversalExpr{
		Traversal: hcl.Traversal{hcl.TraverseRoot{Name: "v", SrcRange: rng}, hcl.TraverseAttr{Name: "revision", SrcRange: rng}},
		SrcRange:  rng,
	}
	return &hclsyntax.ForExpr{
		KeyVar:   "k",
		ValVar:   "v",
		CollExpr: step,
		KeyExpr:  local("k"),
		ValExpr:  revision,
		CondExpr: &hclsyntax.FunctionCallExpr{
			Name: "startswith", Args: []hclsyntax.Expression{local("k"), prefix},
			NameRange: rng, OpenParenRange: rng, CloseParenRange: rng,
		},
		SrcRange: rng, OpenRange: rng, CloseRange: rng,
	}
}

// loopRefs walks a step's module attributes and blocks. In a looping step
// it rewrites each.* and item.* onto the instance object; in any other step
// it reports item, which only means something with for_each.
func loopRefs(attrs hclsyntax.Attributes, blocks hclsyntax.Blocks, looping bool) hcl.Diagnostics {
	var diags hcl.Diagnostics
	visit := func(n hclsyntax.Node) hcl.Diagnostics {
		var diags hcl.Diagnostics
		switch e := n.(type) {
		case *hclsyntax.ForExpr:
			for _, v := range []string{e.KeyVar, e.ValVar} {
				if looping && (v == "each" || v == "item") {
					rng := e.SrcRange
					diags = append(diags, &hcl.Diagnostic{
						Severity: hcl.DiagError,
						Summary:  "Name taken in a looping step",
						Detail:   fmt.Sprintf("Inside a step with for_each, %q already means something. Name the for expression's variable something else.", v),
						Subject:  &rng,
					})
				}
			}
		case *hclsyntax.ScopeTraversalExpr:
			diags = append(diags, rewriteLoopRef(e, looping)...)
		}
		return diags
	}
	for _, a := range attrs {
		diags = append(diags, hclsyntax.VisitAll(a.Expr, visit)...)
	}
	for _, b := range blocks {
		diags = append(diags, hclsyntax.VisitAll(b.Body, visit)...)
	}
	return diags
}

// rewritten remembers the references already mapped onto the instance
// object. The parser caches files, so a circuit can be lowered more than
// once over the same syntax tree, and a second rewrite would nest them.
var rewritten sync.Map // *hclsyntax.ScopeTraversalExpr => struct{}

func rewriteLoopRef(e *hclsyntax.ScopeTraversalExpr, looping bool) hcl.Diagnostics {
	if _, done := rewritten.Load(e); done {
		return nil
	}
	t := e.Traversal
	root := t.RootName()
	if root != "each" && root != "item" {
		return nil
	}
	rng := e.SrcRange
	if root == "item" && !looping {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "item outside a looping step",
			Detail:   "item.key and item.value only exist in a step with for_each.",
			Subject:  &rng,
		}}
	}
	if !looping {
		return nil
	}
	var name string
	if len(t) > 1 {
		if a, isAttr := t[1].(hcl.TraverseAttr); isAttr {
			name = a.Name
		}
	}
	targets := map[string]map[string]string{
		"each": {"key": "host_key", "value": "host"},
		"item": {"key": "item_key", "value": "item"},
	}
	field, known := targets[root][name]
	if !known {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Invalid %s reference", root),
			Detail:   fmt.Sprintf("Use %s.key or %s.value.", root, root),
			Subject:  &rng,
		}}
	}
	sr := t[0].SourceRange()
	rewritten.Store(e, struct{}{})
	e.Traversal = append(hcl.Traversal{
		hcl.TraverseRoot{Name: "each", SrcRange: sr},
		hcl.TraverseAttr{Name: "value", SrcRange: sr},
		hcl.TraverseAttr{Name: field, SrcRange: sr},
	}, t[2:]...)
	return nil
}

// eachMeansHost evaluates expr, from the circuit's ssh block, with each
// bound to the host as in a plain step. The ssh block's syntax is shared by
// every step, so it is wrapped rather than rewritten in place:
//
//	[for each in [{ key = each.value.host_key, value = each.value.host }] : expr][0]
func eachMeansHost(expr hclsyntax.Expression, rng hcl.Range) hclsyntax.Expression {
	lit := func(v cty.Value) *hclsyntax.LiteralValueExpr {
		return &hclsyntax.LiteralValueExpr{Val: v, SrcRange: rng}
	}
	host := &hclsyntax.ObjectConsExpr{
		Items: []hclsyntax.ObjectConsItem{
			{KeyExpr: lit(cty.StringVal("key")), ValueExpr: eachPath(rng, "value", "host_key")},
			{KeyExpr: lit(cty.StringVal("value")), ValueExpr: eachPath(rng, "value", "host")},
		},
		SrcRange: rng, OpenRange: rng,
	}
	return &hclsyntax.IndexExpr{
		Collection: &hclsyntax.ForExpr{
			ValVar:   "each",
			CollExpr: &hclsyntax.TupleConsExpr{Exprs: []hclsyntax.Expression{host}, SrcRange: rng, OpenRange: rng},
			ValExpr:  expr,
			SrcRange: rng, OpenRange: rng, CloseRange: rng,
		},
		Key:      lit(cty.Zero),
		SrcRange: rng, OpenRange: rng, BracketRange: rng,
	}
}
