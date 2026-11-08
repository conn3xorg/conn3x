// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package importid is the format of the ID a step's import hands the
// provider. The circuit lowering writes it as an expression, and the
// import_id provider function builds it from values, so a root import
// block can adopt a step inside a module; both take the version and the
// arguments left out from here.
//
//	{"args":{"path":"/etc/motd"},"key":"web1","ssh":{...},"v":1,"write_only":true}
package importid

import (
	"fmt"
	"strings"

	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

// Version is the format's version, "v" in the ID.
const Version = 1

// LeftOut reports whether an argument stays out of an ID: the content is
// read from the host, and write-only arguments, such as a Windows user's
// password_wo, must not show in plan output.
func LeftOut(name string) bool {
	return name == "content" || name == "validate" || strings.HasSuffix(name, "_wo")
}

// Build returns the ID for one host of a step: key is the host's key in
// the circuit, ssh the circuit's ssh settings and args the step's module
// arguments as written. Null attributes are left out of ssh and args, as
// the lowering does, so the two give the same ID for the same step.
func Build(key string, ssh, args cty.Value) (string, error) {
	sshAttrs, err := attrs("ssh", ssh)
	if err != nil {
		return "", err
	}
	if h, ok := sshAttrs["host"]; !ok || h.Type() != cty.String {
		return "", fmt.Errorf("ssh needs a host")
	}
	argAttrs, err := attrs("args", args)
	if err != nil {
		return "", err
	}
	id := map[string]cty.Value{"v": cty.NumberIntVal(Version), "key": cty.StringVal(key), "ssh": cty.ObjectVal(sshAttrs)}
	if wo, ok := argAttrs["content_wo"]; ok && !wo.IsNull() {
		id["write_only"] = cty.True
	}
	for name := range argAttrs {
		if LeftOut(name) {
			delete(argAttrs, name)
		}
	}
	id["args"] = cty.ObjectVal(argAttrs)
	obj := cty.ObjectVal(id)
	b, err := ctyjson.Marshal(obj, obj.Type())
	return string(b), err
}

// attrs is an object's or map's non-null attributes.
func attrs(what string, v cty.Value) (map[string]cty.Value, error) {
	if v.IsNull() || (!v.Type().IsObjectType() && !v.Type().IsMapType()) {
		return nil, fmt.Errorf("%s must be an object, such as { host = \"203.0.113.10\" }", what)
	}
	out := map[string]cty.Value{}
	for name, a := range v.AsValueMap() {
		if !a.IsNull() {
			out[name] = a
		}
	}
	return out, nil
}
