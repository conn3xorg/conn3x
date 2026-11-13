// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func TestInventoryFunction(t *testing.T) {
	p, _ := New()
	if _, ok := p.GetProviderSchema(ctx).Functions["inventory"]; !ok {
		t.Fatal("inventory isn't in the provider schema")
	}
	call := func(path, group string) providers.CallFunctionResponse {
		return p.CallFunction(ctx, providers.CallFunctionRequest{Name: "inventory", Arguments: []cty.Value{cty.StringVal(path), cty.StringVal(group)}})
	}
	for _, file := range []string{"hosts.ini", "hosts.yml"} {
		path := filepath.Join("..", "convert", "ansible", "testdata", "inv", file)
		resp := call(path, "prod")
		if resp.Error != nil {
			t.Fatalf("%s: %v", file, resp.Error)
		}
		hosts := resp.Result
		web2, db := hosts.GetAttr("web2"), hosts.GetAttr("db1.example.com")
		if web2.GetAttr("address").AsString() != "203.0.113.11" || web2.GetAttr("user").AsString() != "deploy" || web2.Type().HasAttribute("port") {
			t.Errorf("%s: web2 = %#v", file, web2)
		}
		if db.GetAttr("address").AsString() != "db1.example.com" || !db.GetAttr("port").Equals(cty.NumberIntVal(2222)).True() || db.GetAttr("user").AsString() != "admin" {
			t.Errorf("%s: db1 = %#v", file, db)
		}
		if db.GetAttr("vars").Index(cty.StringVal("ansible_user")).AsString() != "admin" {
			t.Errorf("%s: db1's vars = %#v", file, db.GetAttr("vars"))
		}
		if n := len(hosts.Type().AttributeTypes()); n != 3 {
			t.Errorf("%s: prod has %d hosts, want 3", file, n)
		}
		if resp := call(path, "nope"); resp.Error == nil || !strings.Contains(resp.Error.Error(), `has no group "nope"; it has db, prod, `) {
			t.Errorf("%s: unknown group: %v", file, resp.Error)
		}
	}
	if resp := call("does-not-exist.ini", "all"); resp.Error == nil {
		t.Error("a missing file should be an error")
	}
}
