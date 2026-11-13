// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestHostDataFunction(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"hierarchy.yaml":  "hierarchy:\n  - hosts/{host}.yaml\n  - groups/{group}.yaml\n  - common.yaml\n",
		"common.yaml":     "ntp: [pool.ntp.org]\nworkers: 2\n",
		"groups/web.yaml": "workers: 4\n",
		"hosts/web1.yaml": "workers: 8\n",
	} {
		_ = os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	call := func(host string) cty.Value {
		t.Helper()
		resp := hostData([]cty.Value{cty.StringVal(dir), cty.ObjectVal(map[string]cty.Value{
			"host":  cty.StringVal(host),
			"group": cty.TupleVal([]cty.Value{cty.StringVal("web")}),
		})})
		if resp.Error != nil {
			t.Fatal(resp.Error)
		}
		return resp.Result
	}
	r := call("web1")
	if v := r.GetAttr("values").GetAttr("workers"); !v.RawEquals(cty.NumberIntVal(8)) {
		t.Errorf("web1 workers = %#v", v)
	}
	if f := r.GetAttr("from").Index(cty.StringVal("ntp")).AsString(); f != "common.yaml" {
		t.Errorf("ntp from %q", f)
	}
	if v := call("web2").GetAttr("values").GetAttr("workers"); !v.RawEquals(cty.NumberIntVal(4)) {
		t.Errorf("web2 workers = %#v, want the group's 4", v)
	}
	unknown := hostData([]cty.Value{cty.StringVal(dir), cty.ObjectVal(map[string]cty.Value{"host": cty.UnknownVal(cty.String)})})
	if unknown.Error != nil || unknown.Result.IsKnown() {
		t.Errorf("an unknown host: %#v, %v", unknown.Result, unknown.Error)
	}
	if resp := hostData([]cty.Value{cty.StringVal(dir), cty.StringVal("nope")}); resp.Error == nil {
		t.Error("vars as a string passed")
	}
}
