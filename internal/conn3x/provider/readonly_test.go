// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// A read-only attribute in a step or resource used to pass validate and do
// nothing (#1328): service's running, and every type's revision with it.
func TestReadOnlyAttributesAreRefused(t *testing.T) {
	p := &Provider{}
	validate := func(typeName string, attrs map[string]cty.Value) tfdiags.Diagnostics {
		return p.ValidateResourceConfig(t.Context(), providers.ValidateResourceConfigRequest{TypeName: typeName, Config: eosStep(typeName, attrs, nil)}).Diagnostics
	}
	cases := []struct {
		typeName, attr, hint string
		attrs                map[string]cty.Value
	}{
		{"conn3x_service", "running", `state = "started"`, map[string]cty.Value{"name": cty.StringVal("crond"), "running": cty.True}},
		{"conn3x_file", "revision", "read-only", map[string]cty.Value{"path": cty.StringVal("/etc/motd"), "content": cty.StringVal("hi"), "revision": cty.StringVal("1")}},
		{"conn3x_package", "installed_version", "read-only", map[string]cty.Value{"name": cty.StringVal("curl"), "installed_version": cty.UnknownVal(cty.String)}},
	}
	for _, c := range cases {
		d := validate(c.typeName, c.attrs)
		if len(d) != 1 || !tfdiags.GetAttribute(d[0]).Equals(cty.GetAttrPath(c.attr)) || !strings.Contains(d[0].Description().Detail, c.hint) {
			t.Errorf("%s.%s: want one diagnostic on it mentioning %q, got %v", c.typeName, c.attr, c.hint, d.Err())
		}
	}
	// Optional and computed is still settable.
	if d := validate("conn3x_service", map[string]cty.Value{"name": cty.StringVal("crond"), "on_remove": cty.StringVal("delete")}); d.HasErrors() {
		t.Errorf("on_remove is optional: %v", d.Err())
	}
	// Nothing set, nothing refused, for every type.
	for _, typeName := range ResourceTypeNames() {
		schema := resourceTypes[typeName].schema().Block
		if d := validateReadOnly(typeName, schema, schema.EmptyValue()); d.HasErrors() {
			t.Errorf("%s with nothing set: %v", typeName, d.Err())
		}
	}
}
