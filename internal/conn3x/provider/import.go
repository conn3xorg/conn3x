// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"

	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
	"github.com/opentofu/opentofu/internal/conn3x/modules/service"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// A step with import = true adopts what is already on a host. The circuit
// lowering writes an import block whose ID is JSON (see conn3x_import.go in
// internal/configs):
//
//	{"v":1,"key":"web1","ssh":{...},"args":{"path":"/etc/motd"},"write_only":true}
//
// ssh says how to reach the host, args are the step's own arguments except
// content, and write_only says the content goes to content_wo, so the
// import must keep it out of state too.

const importVersion = 1

type importID struct {
	V         int                        `json:"v"`
	Key       string                     `json:"key"`
	SSH       json.RawMessage            `json:"ssh"`
	Args      map[string]json.RawMessage `json:"args"`
	WriteOnly bool                       `json:"write_only"`
}

// importable maps each resource type a step can adopt to what names the
// object in its id, and how to tell whether the host has it after a read.
var importable = map[string]struct {
	id     func(state cty.Value) []string
	exists func(read cty.Value) bool
	what   string
}{
	"conn3x_file":      {pathID(""), notNull, "file %s"},
	"conn3x_directory": {pathID("directory"), notNull, "directory %s"},
	"conn3x_link":      {pathID("link"), notNull, "link %s"},
	"conn3x_package":   {nameID("package", nil), observed("installed_version"), "package %s"},
	"conn3x_service":   {nameID("service", service.Unit), observed("running"), "service %s"},
	"conn3x_user":      {nameID("user", nil), observed("uid"), "user %s"},
	"conn3x_group":     {nameID("group", nil), observed("gid"), "group %s"},
}

func pathID(kind string) func(cty.Value) []string {
	return func(v cty.Value) []string {
		if kind == "" {
			return []string{v.GetAttr("path").AsString()}
		}
		return []string{kind, v.GetAttr("path").AsString()}
	}
}

func nameID(kind string, norm func(string) string) func(cty.Value) []string {
	return func(v cty.Value) []string {
		name := v.GetAttr("name").AsString()
		if norm != nil {
			name = norm(name)
		}
		return []string{kind, name}
	}
}

func notNull(v cty.Value) bool { return !v.IsNull() }

func observed(attr string) func(cty.Value) bool {
	return func(v cty.Value) bool { return !v.IsNull() && !v.GetAttr(attr).IsNull() }
}

func (p *Provider) ImportResourceState(ctx context.Context, req providers.ImportResourceStateRequest) providers.ImportResourceStateResponse {
	var resp providers.ImportResourceStateResponse
	kind, ok := importable[req.TypeName]
	if !ok {
		resp.Diagnostics = unsupported("importing " + req.TypeName)
		return resp
	}
	id, prior, err := importPrior(req.TypeName, req.Target.ID)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.Sourceless(tfdiags.Error, "Invalid import ID", err.Error()))
		return resp
	}

	// Read here rather than leave it to the refresh that follows, so a
	// missing object gets an error that says what to do about it.
	ctx, done := p.withStop(ctx)
	defer done()
	read := resourceTypes[req.TypeName].read(ctx, providers.ReadResourceRequest{TypeName: req.TypeName, PriorState: prior})
	resp.Diagnostics = resp.Diagnostics.Append(read.Diagnostics)
	if resp.Diagnostics.HasErrors() {
		return resp
	}
	if !kind.exists(read.NewState) {
		what := fmt.Sprintf(kind.what, kind.id(prior)[len(kind.id(prior))-1])
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.Sourceless(tfdiags.Error,
			fmt.Sprintf("Nothing to import on %s", id.Key),
			fmt.Sprintf("The step imports %s on %s, but %s doesn't have it, so there's nothing to adopt. "+
				"Remove %s from the step's import, or set import to the hosts that already have it; "+
				"Conn3x then creates it on the rest.", what, id.Key, id.Key, id.Key)))
		return resp
	}
	resp.ImportedResources = []providers.ImportedResource{{TypeName: req.TypeName, State: adopted(req.TypeName, read.NewState)}}
	return resp
}

// importPrior decodes an import ID into the state a read starts from.
func importPrior(typeName, raw string) (importID, cty.Value, error) {
	var id importID
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&id); err != nil {
		return id, cty.NilVal, fmt.Errorf("a step's import ID is JSON written by the circuit, and this one doesn't read: %w", err)
	}
	if id.V != importVersion {
		return id, cty.NilVal, fmt.Errorf("import ID version %d isn't one this Conn3x reads (it reads %d); was it written by a newer Conn3x?", id.V, importVersion)
	}
	if id.Key == "" || len(id.SSH) == 0 {
		return id, cty.NilVal, fmt.Errorf("import ID needs key and ssh")
	}
	attrs := map[string]json.RawMessage{"ssh": id.SSH}
	for k, v := range id.Args {
		if k == "ssh" || k == "content" || k == "content_wo" || k == "validate" {
			return id, cty.NilVal, fmt.Errorf("import ID args can't hold %s", k)
		}
		attrs[k] = v
	}
	b, err := json.Marshal(attrs)
	if err != nil {
		return id, cty.NilVal, err
	}
	ty := resourceTypes[typeName].schema().Block.ImpliedType()
	// Attributes left out decode as null; an unknown one is an error.
	v, err := ctyjson.Unmarshal(b, ty)
	if err != nil {
		return id, cty.NilVal, fmt.Errorf("import ID for %s: %w", typeName, err)
	}
	for _, need := range []string{"path", "name"} {
		if ty.HasAttribute(need) && v.GetAttr(need).IsNull() {
			return id, cty.NilVal, fmt.Errorf("import ID for %s has no %s", typeName, need)
		}
	}
	if v.GetAttr("ssh").GetAttr("host").IsNull() {
		return id, cty.NilVal, fmt.Errorf("import ID has no ssh host")
	}
	vals := v.AsValueMap()
	if vals["on_remove"].IsNull() {
		vals["on_remove"] = cty.StringVal(defaultOnRemove)
	}
	if typeName == "conn3x_package" && vals["state"].IsNull() {
		vals["state"] = cty.StringVal(string(pkg.Present)) // what planPackage defaults it to
	}
	if id.WriteOnly {
		if typeName != "conn3x_file" {
			return id, cty.NilVal, fmt.Errorf("write_only applies to files only")
		}
		// Make sure there is a key: the read hashes the content with it,
		// so the content itself never reaches state.
		if _, err := hmacKey(true); err != nil {
			return id, cty.NilVal, err
		}
		vals["content_hmac"] = cty.UnknownVal(cty.String)
	}
	vals["id"] = cty.StringVal(strings.Join(append([]string{hostPort(vals["ssh"])}, importable[typeName].id(cty.ObjectVal(vals))...), ":"))
	return id, cty.ObjectVal(vals), nil
}

// adopted is a freshly read object with the arguments the step sets but a
// read doesn't fill taken from the host, so a plan shows how the host
// differs from the step rather than how the step differs from nothing.
func adopted(typeName string, read cty.Value) cty.Value {
	if typeName != "conn3x_service" {
		return read
	}
	vals := read.AsValueMap()
	if !vals["state"].IsNull() {
		vals["state"] = cty.StringVal(string(service.Stopped))
		if vals["running"].True() {
			vals["state"] = cty.StringVal(string(service.Started))
		}
	}
	if !vals["enabled"].IsNull() {
		vals["enabled"] = vals["is_enabled"]
	}
	return cty.ObjectVal(vals)
}
