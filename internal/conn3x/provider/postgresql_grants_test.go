// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func setMap(m map[string][]string) cty.Value {
	vals := map[string]cty.Value{}
	for k, ps := range m {
		set := make([]cty.Value, len(ps))
		for i, p := range ps {
			set[i] = cty.StringVal(p)
		}
		vals[k] = cty.SetVal(set)
	}
	return cty.MapVal(vals)
}

// tables_created_by is planned from the configuration, or from what apply
// resolved before, or unknown until apply reads the schema's owner; and it
// can only name a schema table_grants lists.
func TestPlanPgRoleGrants(t *testing.T) {
	r := resourceTypes["conn3x_postgresql_role"]
	cfg := objFor(r.schema(), map[string]cty.Value{
		"name":            cty.StringVal("app"),
		"database_grants": setMap(map[string][]string{"shop": {"CONNECT"}}),
		"table_grants":    setMap(map[string][]string{"shop.sales": {"SELECT"}, "shop.audit": {"SELECT"}}),
	})
	if diags := r.validate(cfg); diags.HasErrors() {
		t.Fatal(diags.Err())
	}
	created := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
	if c := created.GetAttr("tables_created_by"); c.IsWhollyKnown() || c.LengthInt() != 2 {
		t.Errorf("a new step's tables_created_by is %#v, want two unknown", c)
	}

	prior := created.AsValueMap()
	prior["id"], prior["in_sync"] = cty.StringVal("203.0.113.10:postgresql_role:app"), cty.True
	prior["revision"] = cty.StringVal("r")
	prior["tables_created_by"] = cty.MapVal(map[string]cty.Value{"shop.sales": cty.StringVal("migrator"), "shop.audit": cty.StringVal("migrator")})
	withCreator := objFor(r.schema(), map[string]cty.Value{
		"name":              cty.StringVal("app"),
		"database_grants":   setMap(map[string][]string{"shop": {"CONNECT"}}),
		"table_grants":      setMap(map[string][]string{"shop.sales": {"SELECT"}, "shop.audit": {"SELECT"}}),
		"tables_created_by": cty.MapVal(map[string]cty.Value{"shop.audit": cty.StringVal("auditor")}),
	})
	planned := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.ObjectVal(prior), ProposedNewState: withCreator, Config: withCreator}).PlannedState
	want := cty.MapVal(map[string]cty.Value{"shop.sales": cty.StringVal("migrator"), "shop.audit": cty.StringVal("auditor")})
	if got := planned.GetAttr("tables_created_by"); !got.RawEquals(want) {
		t.Errorf("tables_created_by planned as %#v, want %#v", got, want)
	}

	bad := objFor(r.schema(), map[string]cty.Value{
		"name":              cty.StringVal("app"),
		"table_grants":      setMap(map[string][]string{"shop.sales": {"SELECT"}}),
		"tables_created_by": cty.MapVal(map[string]cty.Value{"shop.other": cty.StringVal("x")}),
	})
	if diags := r.validate(bad); !diags.HasErrors() || !strings.Contains(diags.Err().Error(), "doesn't list") {
		t.Errorf("tables_created_by for a schema without table_grants: %v", diags.Err())
	}
	worse := objFor(r.schema(), map[string]cty.Value{
		"name":          cty.StringVal("app"),
		"schema_grants": setMap(map[string][]string{"sales": {"USAGE"}}),
	})
	if diags := r.validate(worse); !diags.HasErrors() || !strings.Contains(diags.Err().Error(), "database.schema") {
		t.Errorf("a schema_grants key without its database: %v", diags.Err())
	}
}
