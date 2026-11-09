// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/addrs"
	"github.com/opentofu/opentofu/internal/conn3x/importid"
)

// A step's import argument adopts what is already on its hosts. It lowers
// to an ordinary import block, so OpenTofu plans it like any other import
// and skips it once the step is in state:
//
//	step "motd" { import = true  file { path = "/etc/motd" ... } }
//
// becomes
//
//	import {
//	  for_each = <the step's for_each>
//	  to       = conn3x_file.web__motd[each.key]
//	  id       = jsonencode({ v = 1, key = each.key, ssh = {...}, args = { path = "/etc/motd", ... } })
//	}
//
// The provider gets only the ID, so it carries what a read needs: how to
// reach the host and the step's arguments. Nulls are left out to keep the
// "imported from" line in plan output short.

// importModules are the modules a step can import, by resource type.
var importModules = map[string]string{
	"conn3x_file":      "file",
	"conn3x_directory": "directory",
	"conn3x_link":      "link",
	"conn3x_package":   "package",
	"conn3x_service":   "service",
	"conn3x_user":      "user",
	"conn3x_group":     "group",

	"conn3x_authorized_key":   "authorized_key",
	"conn3x_cron":             "cron",
	"conn3x_timer":            "timer",
	"conn3x_sysctl":           "sysctl",
	"conn3x_mount":            "mount",
	"conn3x_repository":       "repository",
	"conn3x_hostname":         "hostname",
	"conn3x_timezone":         "timezone",
	"conn3x_locale":           "locale",
	"conn3x_firewalld":        "firewalld",
	"conn3x_ufw_rule":         "ufw",
	"conn3x_selinux_boolean":  "selinux_boolean",
	"conn3x_selinux_fcontext": "selinux_fcontext",

	"conn3x_postgresql_database": "postgresql_database",
	"conn3x_postgresql_role":     "postgresql_role",

	"conn3x_windows_file":           "windows_file",
	"conn3x_windows_directory":      "windows_directory",
	"conn3x_windows_service":        "windows_service",
	"conn3x_windows_registry_value": "windows_registry_value",
	"conn3x_windows_feature":        "windows_feature",
	"conn3x_windows_user":           "windows_user",
	"conn3x_windows_group":          "windows_group",
	"conn3x_windows_package":        "windows_package",
}

// ImportableType is the resource type a module's step lowers to, when the
// module can import; conn3x generate step takes the same modules.
func ImportableType(module string) (string, bool) {
	for typ, m := range importModules {
		if m == module {
			return typ, true
		}
	}
	return "", false
}

func stepImport(r *Resource, attr *hclsyntax.Attribute, moduleAttrs hclsyntax.Attributes, ssh *hclsyntax.Block) (*Import, hcl.Diagnostics) {
	rng := attr.SrcRange
	if _, ok := importModules[r.Type]; !ok {
		var names []string
		for _, m := range importModules {
			names = append(names, fmt.Sprintf("%q", m))
		}
		sort.Strings(names)
		names = append(names, `"template"`)
		return nil, hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Step can't import",
			Detail:   fmt.Sprintf("import works on steps using %s for now.", strings.Join(names, ", ")),
			Subject:  attr.NameRange.Ptr(),
		}}
	}

	forEach := r.ForEach
	if v, diags := attr.Expr.Value(nil); !diags.HasErrors() && v.Type() == cty.Bool {
		if v.IsNull() || v.False() {
			return nil, nil
		}
	} else {
		forEach = &importHosts{all: r.ForEach, hosts: unfiltered(r.ForEach), keys: attr.Expr}
	}

	lit := func(v cty.Value) *hclsyntax.LiteralValueExpr {
		return &hclsyntax.LiteralValueExpr{Val: v, SrcRange: rng}
	}
	object := func(attrs map[string]hclsyntax.Expression) *hclsyntax.ObjectConsExpr {
		names := make([]string, 0, len(attrs))
		for name := range attrs {
			names = append(names, name)
		}
		sort.Strings(names)
		obj := &hclsyntax.ObjectConsExpr{SrcRange: rng, OpenRange: rng}
		for _, name := range names {
			obj.Items = append(obj.Items, hclsyntax.ObjectConsItem{KeyExpr: lit(cty.StringVal(name)), ValueExpr: attrs[name]})
		}
		return obj
	}
	local := func(name string) *hclsyntax.ScopeTraversalExpr {
		return &hclsyntax.ScopeTraversalExpr{Traversal: hcl.Traversal{hcl.TraverseRoot{Name: name, SrcRange: rng}}, SrcRange: rng}
	}
	// { for k, v in obj : k => v if v != null }
	withoutNulls := func(obj hclsyntax.Expression) hclsyntax.Expression {
		return &hclsyntax.ForExpr{
			KeyVar: "k", ValVar: "v", CollExpr: obj, KeyExpr: local("k"), ValExpr: local("v"),
			CondExpr: &hclsyntax.BinaryOpExpr{LHS: local("v"), Op: hclsyntax.OpNotEqual, RHS: lit(cty.NullVal(cty.DynamicPseudoType)), SrcRange: rng},
			SrcRange: rng, OpenRange: rng, CloseRange: rng,
		}
	}

	sshAttrs := map[string]hclsyntax.Expression{}
	for name, a := range ssh.Body.Attributes {
		sshAttrs[name] = a.Expr
	}
	args := map[string]hclsyntax.Expression{}
	for name, a := range moduleAttrs {
		if !importid.LeftOut(name) {
			args[name] = a.Expr
		}
	}
	id := map[string]hclsyntax.Expression{
		"v":    lit(cty.NumberIntVal(importid.Version)),
		"key":  eachTraversal("key", rng),
		"ssh":  withoutNulls(object(sshAttrs)),
		"args": withoutNulls(object(args)),
	}
	if _, wo := moduleAttrs["content_wo"]; wo {
		id["write_only"] = lit(cty.True)
	}

	step := &hclsyntax.ScopeTraversalExpr{
		Traversal: hcl.Traversal{hcl.TraverseRoot{Name: r.Type, SrcRange: rng}, hcl.TraverseAttr{Name: r.Name, SrcRange: rng}},
		SrcRange:  rng,
	}
	return &Import{
		ID: &hclsyntax.FunctionCallExpr{
			Name: "jsonencode", Args: []hclsyntax.Expression{object(id)},
			NameRange: rng, OpenParenRange: rng, CloseParenRange: rng,
		},
		To: &hclsyntax.IndexExpr{Collection: step, Key: eachTraversal("key", rng), SrcRange: rng, OpenRange: rng, BracketRange: rng},
		StaticTo: addrs.ConfigResource{
			Module:   addrs.RootModule,
			Resource: addrs.Resource{Mode: addrs.ManagedResourceMode, Type: r.Type, Name: r.Name},
		},
		ForEach:   forEach,
		DeclRange: rng,
	}, nil
}

// importHosts is the step's for_each cut down to the hosts its import
// lists. A name that isn't one of the step's hosts is an error, so a typo
// can't quietly turn an adopt into a create. In a looping step a host name
// stands for all of that host's instances.
type importHosts struct {
	// all is the step's instances, hosts the same before its when.
	all, hosts, keys hcl.Expression
}

var _ hcl.Expression = (*importHosts)(nil)

func (h *importHosts) Value(ctx *hcl.EvalContext) (cty.Value, hcl.Diagnostics) {
	all, diags := h.all.Value(ctx)
	keys, keyDiags := h.keys.Value(ctx)
	diags = append(diags, keyDiags...)
	if diags.HasErrors() {
		return cty.DynamicVal, diags
	}
	all, marks := all.Unmark()
	if !all.IsWhollyKnown() || !keys.IsWhollyKnown() {
		return cty.DynamicVal.WithMarks(marks), diags
	}
	rng := h.keys.Range()
	bad := func(detail string) (cty.Value, hcl.Diagnostics) {
		return cty.DynamicVal, append(diags, &hcl.Diagnostic{Severity: hcl.DiagError, Summary: "Invalid import in step", Detail: detail, Subject: &rng})
	}
	keys, _ = keys.Unmark()
	if keys.IsNull() || !(keys.Type().IsListType() || keys.Type().IsSetType() || keys.Type().IsTupleType()) {
		return bad("import is true, false, or a list of host names.")
	}
	instances := map[string]cty.Value{}
	if !all.IsNull() {
		for it := all.ElementIterator(); it.Next(); {
			k, v := it.Element()
			instances[k.AsString()] = v
		}
	}
	picked := map[string]cty.Value{}
	for it := keys.ElementIterator(); it.Next(); {
		_, k := it.Element()
		if k.IsNull() || k.Type() != cty.String {
			return bad("import is true, false, or a list of host names.")
		}
		name, found := k.AsString(), false
		for key, v := range instances {
			if key == name || strings.HasPrefix(key, name+"/") {
				picked[key], found = v, true
			}
		}
		if !found {
			if h.hosts != h.all && h.leftOut(ctx, name) {
				if _, once := h.all.(*onceFilter); once {
					return bad(fmt.Sprintf("import names %q, but the step has run_once and runs on another host, so it has nothing to adopt there.", name))
				}
				return bad(fmt.Sprintf("import names %q, but the step's when is false there, so the step doesn't run on it and has nothing to adopt.", name))
			}
			return bad(fmt.Sprintf("import names %q, which isn't one of this step's hosts.", name))
		}
	}
	if len(picked) == 0 {
		return cty.EmptyObjectVal.WithMarks(marks), diags
	}
	return cty.ObjectVal(picked).WithMarks(marks), diags
}

// leftOut reports whether name is one of the step's hosts that its when
// skips.
func (h *importHosts) leftOut(ctx *hcl.EvalContext, name string) bool {
	hosts, diags := h.hosts.Value(ctx)
	hosts, _ = hosts.Unmark()
	if diags.HasErrors() || !hosts.IsKnown() || hosts.IsNull() {
		return false
	}
	for it := hosts.ElementIterator(); it.Next(); {
		k, _ := it.Element()
		if key := k.AsString(); key == name || strings.HasPrefix(key, name+"/") {
			return true
		}
	}
	return false
}

func (h *importHosts) Variables() []hcl.Traversal {
	return append(append([]hcl.Traversal{}, h.all.Variables()...), h.keys.Variables()...)
}

func (h *importHosts) Range() hcl.Range      { return h.keys.Range() }
func (h *importHosts) StartRange() hcl.Range { return h.keys.StartRange() }
