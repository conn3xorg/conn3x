// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
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

// cluster answers psql on any database: the role's privileges on database
// app, on its schema public, which app owns, and on mine, which the role
// owns. Unless stuck, a transaction's grants and revokes take effect.
type cluster struct {
	db, schema, tables []string
	stuck              bool
	fail               string // SQL holding this exits 1
	sent               []string
}

func (c *cluster) Run(_ context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	sql := string(stdin)
	c.sent = append(c.sent, cmd+"\n"+sql)
	js := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	switch {
	case c.fail != "" && strings.Contains(sql, c.fail):
		return ssh.Result{ExitCode: 1, Stderr: []byte("ERROR:  permission denied")}, nil
	case strings.Contains(sql, "FROM pg_database"):
		return ssh.Result{Stdout: []byte(`{"app": {"owned": false, "privs": ` + js(c.db) + `}}` + "\n")}, nil
	case strings.Contains(sql, "FROM pg_namespace") && strings.HasSuffix(cmd, "-d 'app'"):
		return ssh.Result{Stdout: []byte(`{"public": {"owner": "app", "owned": false, "schema": ` + js(c.schema) + `, "tables": [` + js(c.tables) + `], "defaults": {"app": ` + js(c.tables) + `}}, ` +
			`"mine": {"owner": "web", "owned": true, "schema": [], "tables": null, "defaults": {}}}` + "\n")}, nil
	case strings.HasPrefix(sql, "\\set VERBOSITY terse\nSET standard_conforming_strings = on;\nBEGIN;") && !c.stuck:
		apply := func(on string, have []string) []string {
			for _, line := range strings.Split(sql, "\n") {
				verb, rest, _ := strings.Cut(line, " ")
				ps, obj, ok := strings.Cut(rest, " ON ")
				if !ok || !strings.HasPrefix(obj, on) || verb != "GRANT" && verb != "REVOKE" {
					continue
				}
				for _, p := range strings.Split(ps, ", ") {
					have = slices.DeleteFunc(have, func(h string) bool { return h == p || p == "ALL" })
					if verb == "GRANT" {
						have = append(have, p)
					}
				}
			}
			return have
		}
		if strings.HasSuffix(cmd, "-d postgres") {
			c.db = apply("DATABASE", c.db)
		} else {
			c.schema, c.tables = apply("SCHEMA", c.schema), apply("ALL TABLES", c.tables)
		}
	}
	return ssh.Result{}, nil
}

func TestApplyGrants(t *testing.T) {
	ctx := context.Background()
	g := Grants{Databases: map[string][]string{"app": {"CONNECT"}}, Schemas: map[string]SchemaGrant{"app.public": {Schema: []string{"USAGE"}, Tables: []string{"SELECT"}}}}
	c := &cluster{db: []string{"CONNECT", "CREATE"}, schema: []string{}, tables: []string{"INSERT"}}
	got, err := ApplyGrants(ctx, c, "web", g)
	if err != nil {
		t.Fatal(err)
	}
	if got.Schemas["app.public"].CreatedBy != "app" {
		t.Errorf("CreatedBy = %q, want the schema's owner", got.Schemas["app.public"].CreatedBy)
	}
	all := strings.Join(c.sent, "\n---\n")
	for _, want := range []string{
		`REVOKE CREATE ON DATABASE "app" FROM "web";`,
		`ALTER DEFAULT PRIVILEGES FOR ROLE "app" IN SCHEMA "public" GRANT SELECT ON TABLES TO "web";`,
	} {
		if !strings.Contains(all, want) {
			t.Errorf("never sent %q", want)
		}
	}
	if strings.Contains(all, `SCHEMA "mine"`) {
		t.Error("revoked on a schema the role owns")
	}

	c = &cluster{db: []string{"CREATE"}, stuck: true}
	if _, err := ApplyGrants(ctx, c, "web", Grants{Databases: map[string][]string{"app": {"CONNECT"}}}); err == nil || !strings.Contains(err.Error(), "aren't as listed after the change") {
		t.Errorf("stuck: %v", err)
	}
	for name, tc := range map[string]struct {
		c    *cluster
		g    Grants
		want string
	}{
		"no schema":     {&cluster{}, Grants{Schemas: map[string]SchemaGrant{"app.sales": {}}}, "schema app.sales doesn't exist"},
		"no database":   {&cluster{}, Grants{Schemas: map[string]SchemaGrant{"shop.sales": {}}}, "database shop doesn't exist"},
		"owned schema":  {&cluster{}, Grants{Schemas: map[string]SchemaGrant{"app.mine": {}}}, "owns schema app.mine"},
		"read fails":    {&cluster{fail: "pg_database"}, g, "psql: ERROR:  permission denied"},
		"schemas fail":  {&cluster{fail: "pg_namespace"}, g, "permission denied"},
		"grant fails":   {&cluster{fail: "BEGIN;\nGRANT"}, Grants{Databases: map[string][]string{"app": {"CONNECT"}}}, "permission denied"},
		"schema grants": {&cluster{fail: "REVOKE ALL ON SCHEMA"}, g, "permission denied"},
		"invalid":       {&cluster{}, Grants{Databases: map[string][]string{"": {"CONNECT"}}}, "database name is empty"},
	} {
		if _, err := ApplyGrants(ctx, tc.c, "web", tc.g); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
	garbled := &server{reply: func(string) (string, string, int) { return "not json\n", "", 0 }}
	if _, err := ReadGrants(ctx, garbled, "web", nil); err == nil || !strings.Contains(err.Error(), "reading database privileges") {
		t.Errorf("garbled: %v", err)
	}
	long := strings.Repeat("x", 64)
	for _, bad := range []Grants{
		{Schemas: map[string]SchemaGrant{long + ".public": {}}},
		{Schemas: map[string]SchemaGrant{"app." + long: {}}},
		{Schemas: map[string]SchemaGrant{"app.public": {CreatedBy: long}}},
	} {
		if bad.Validate() == nil {
			t.Errorf("%+v passed", bad)
		}
	}
}
