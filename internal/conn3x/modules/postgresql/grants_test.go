// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"slices"
	"strings"
	"testing"
)

func TestGrantsValidate(t *testing.T) {
	for _, bad := range []Grants{
		{Databases: map[string][]string{"app": {"SELECT"}}},
		{Schemas: map[string]SchemaGrant{"public": {Schema: []string{"USAGE"}}}},
		{Schemas: map[string]SchemaGrant{"app.public": {Schema: []string{"SELECT"}}}},
		{Schemas: map[string]SchemaGrant{"app.public": {Tables: []string{"USAGE"}}}},
		{Schemas: map[string]SchemaGrant{".public": {}}},
	} {
		if bad.Validate() == nil {
			t.Errorf("%+v passed", bad)
		}
	}
	good := Grants{Databases: map[string][]string{"app": {"CONNECT", "TEMPORARY"}}, Schemas: map[string]SchemaGrant{"app.sales": {Schema: []string{"USAGE"}, Tables: []string{"SELECT"}}}}
	if err := good.Validate(); err != nil {
		t.Error(err)
	}
}

// What the server has beyond the list is named, whole-list within what the
// list reaches: database privileges anywhere, schema and table privileges
// only in the databases it names; defaults for another creator count too.
func TestGrantsExtraAndMatches(t *testing.T) {
	g := Grants{
		Databases: map[string][]string{"shop": {"CONNECT"}},
		Schemas:   map[string]SchemaGrant{"shop.sales": {Schema: []string{"USAGE"}, Tables: []string{"SELECT"}}},
	}
	s := GrantsState{
		Databases: map[string][]string{"shop": {"CONNECT", "CREATE"}, "other": {"CONNECT"}},
		Schemas: map[string]SchemaState{
			"shop.sales":  {Owner: "migrator", Schema: []string{"USAGE"}, Tables: []string{"SELECT"}, AnyTable: []string{"INSERT", "SELECT"}, HasTables: true, Defaults: map[string][]string{"migrator": {"SELECT"}, "old": {"SELECT"}}},
			"shop.public": {Owner: "pg_database_owner", Schema: []string{"USAGE"}, Defaults: map[string][]string{}},
		},
	}
	g = g.WithCreators(s)
	if g.Schemas["shop.sales"].CreatedBy != "migrator" {
		t.Fatalf("CreatedBy %q", g.Schemas["shop.sales"].CreatedBy)
	}
	extra, err := g.Extra(s)
	want := []string{"CREATE on database shop", "CONNECT on database other", "USAGE on schema shop.public", "INSERT on tables in shop.sales", "SELECT by default on tables old makes in shop.sales"}
	if err != nil || len(extra) != len(want) {
		t.Fatalf("extra %q, %v", extra, err)
	}
	for _, w := range want {
		if !slices.Contains(extra, w) {
			t.Errorf("no %q in %q", w, extra)
		}
	}
	if g.Matches(s) {
		t.Error("matches with extra privileges")
	}

	exact := GrantsState{
		Databases: map[string][]string{"shop": {"CONNECT"}},
		Schemas: map[string]SchemaState{
			"shop.sales": {Owner: "migrator", Schema: []string{"USAGE"}, Tables: []string{"SELECT"}, AnyTable: []string{"SELECT"}, HasTables: true, Defaults: map[string][]string{"migrator": {"SELECT"}}},
		},
	}
	if !g.Matches(exact) {
		t.Error("an exact match doesn't match")
	}
	// A schema with no tables of anyone else's has whatever table
	// privileges are wanted.
	empty := exact
	empty.Schemas = map[string]SchemaState{"shop.sales": {Owner: "migrator", Schema: []string{"USAGE"}, Tables: []string{}, AnyTable: []string{}, Defaults: map[string][]string{"migrator": {"SELECT"}}}}
	if !g.Matches(empty) {
		t.Error("a schema with no tables never matches")
	}
	// Grants the list doesn't reach aren't looked at: no database_grants.
	if extra, _ := (Grants{Schemas: g.Schemas}).Extra(s); slices.ContainsFunc(extra, func(e string) bool { return strings.Contains(e, "database") }) {
		t.Errorf("database privileges named without database_grants: %q", extra)
	}
}

// An object the role owns can't be listed: the owner has every privilege.
func TestGrantsOwned(t *testing.T) {
	s := GrantsState{Owned: []string{"app", "app.public"}, Schemas: map[string]SchemaState{"app.public": {}}}
	if _, err := (Grants{Databases: map[string][]string{"app": {"CONNECT"}}}).Extra(s); err == nil || !strings.Contains(err.Error(), "owns database app") {
		t.Errorf("owned database: %v", err)
	}
	if _, err := (Grants{Schemas: map[string]SchemaGrant{"app.public": {Schema: []string{"USAGE"}}}}).Extra(s); err == nil || !strings.Contains(err.Error(), "owns schema app.public") {
		t.Errorf("owned schema: %v", err)
	}
}

func TestIntersectUnion(t *testing.T) {
	all, any := intersectUnion([][]string{{"SELECT", "INSERT"}, {"SELECT"}, {"SELECT", "UPDATE"}})
	if !slices.Equal(all, []string{"SELECT"}) || !slices.Equal(any, []string{"INSERT", "SELECT", "UPDATE"}) {
		t.Errorf("all %q any %q", all, any)
	}
}
