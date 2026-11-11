// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
)

// Privileges a grant can list, by kind of object, as PostgreSQL names them.
var (
	DatabasePrivileges = []string{"CONNECT", "CREATE", "TEMPORARY"}
	SchemaPrivileges   = []string{"CREATE", "USAGE"}
	TablePrivileges    = []string{"DELETE", "INSERT", "REFERENCES", "SELECT", "TRIGGER", "TRUNCATE", "UPDATE"}
)

// SchemaGrant is what a role has on one schema: privileges on the schema
// itself, and on every table in it, now and made later by CreatedBy.
type SchemaGrant struct {
	Schema, Tables []string
	CreatedBy      string
}

// Grants is a role's privileges. Databases, when not nil, is the whole
// list of database privileges, by database. Schemas, when not nil, is the
// whole list of schema and table privileges, keyed "database.schema", in
// the databases it names; other databases aren't read or changed.
type Grants struct {
	Databases map[string][]string
	Schemas   map[string]SchemaGrant
}

// SplitSchemaKey splits "database.schema" at the first dot. A database name
// with a dot in it can't be keyed this way.
func SplitSchemaKey(k string) (db, schema string, err error) {
	db, schema, ok := strings.Cut(k, ".")
	if !ok || db == "" || schema == "" {
		return "", "", fmt.Errorf("schema_grants key %q must be database.schema, such as \"app.public\"", k)
	}
	return db, schema, nil
}

func validPrivileges(what string, got, allowed []string) error {
	for _, p := range got {
		if !slices.Contains(allowed, p) {
			return fmt.Errorf("%q isn't a %s privilege; use %s", p, what, strings.Join(allowed, ", "))
		}
	}
	return nil
}

// Validate checks grants before anything runs.
func (g Grants) Validate() error {
	for db, ps := range g.Databases {
		if err := validName("database", db); err != nil {
			return err
		}
		if err := validPrivileges("database", ps, DatabasePrivileges); err != nil {
			return fmt.Errorf("database_grants %s: %w", db, err)
		}
	}
	for k, sg := range g.Schemas {
		db, schema, err := SplitSchemaKey(k)
		if err != nil {
			return err
		}
		if err := validName("database", db); err != nil {
			return err
		}
		if err := validName("schema", schema); err != nil {
			return err
		}
		if err := validPrivileges("schema", sg.Schema, SchemaPrivileges); err != nil {
			return fmt.Errorf("schema_grants %s: %w", k, err)
		}
		if err := validPrivileges("table", sg.Tables, TablePrivileges); err != nil {
			return fmt.Errorf("schema_grants %s: %w", k, err)
		}
		if sg.CreatedBy != "" {
			if err := validName("role", sg.CreatedBy); err != nil {
				return err
			}
		}
	}
	return nil
}

// SchemaState is what a role has on one schema as the server has it.
type SchemaState struct {
	Owner  string
	Schema []string
	// Tables are the privileges every table in the schema has for the
	// role, and AnyTable those at least one has: they differ while tables
	// disagree. HasTables is false in a schema with no tables but the
	// role's own, where every table has whatever is wanted.
	Tables, AnyTable []string
	HasTables        bool
	// Defaults are the default privileges on tables, by the role whose
	// new tables get them.
	Defaults map[string][]string
}

// GrantsState is a role's privileges as the server has them: on every
// database, and on every schema in the databases asked about.
type GrantsState struct {
	Databases map[string][]string
	Schemas   map[string]SchemaState
	// Owned are the databases and "database.schema" keys the role owns,
	// where it has every privilege whatever is granted.
	Owned []string
}

// psqlIn is psql on another database.
func psqlIn(db string) string {
	return strings.TrimSuffix(psql, "-d postgres") + "-d " + shellQuote(db)
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// runIn runs sql in the database db.
func runIn(ctx context.Context, r modules.Runner, db, sql string) (string, error) {
	if db == "postgres" {
		return run(ctx, r, sql)
	}
	return runCmd(ctx, r, psqlIn(db), sql)
}

// privs is SQL for the role's privileges in an ACL column, as a sorted
// JSON array: what aclexplode lists for it as grantee.
func privs(acl, role string) string {
	return "coalesce((SELECT json_agg(DISTINCT a.privilege_type ORDER BY a.privilege_type) FROM aclexplode(" + acl + ") a WHERE a.grantee = " + role + "), '[]'::json)"
}

// ReadGrants reads role's privileges on every database, and on every schema
// and table in dbs.
func ReadGrants(ctx context.Context, r modules.Runner, role string, dbs []string) (GrantsState, error) {
	s := GrantsState{Databases: map[string][]string{}, Schemas: map[string]SchemaState{}}
	oid := "(SELECT oid FROM pg_roles WHERE rolname = " + literal(role) + ")"
	out, err := run(ctx, r, "SELECT coalesce(json_object_agg(datname, json_build_object('owned', datdba = "+oid+", 'privs', "+privs("datacl", oid)+")), '{}'::json) FROM pg_database WHERE datallowconn;")
	if err != nil {
		return s, err
	}
	var dbRows map[string]struct {
		Owned bool
		Privs []string
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &dbRows); err != nil {
		return s, fmt.Errorf("reading database privileges: %w", err)
	}
	for name, row := range dbRows {
		if row.Owned {
			s.Owned = append(s.Owned, name)
		}
		if len(row.Privs) > 0 {
			s.Databases[name] = row.Privs
		}
	}
	for _, db := range dbs {
		if _, ok := dbRows[db]; !ok {
			return s, fmt.Errorf("database %s doesn't exist, or doesn't take connections", db)
		}
		// Tables the role owns are left out: an owner has every privilege.
		tables := "SELECT c.relacl FROM pg_class c WHERE c.relnamespace = n.oid AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND c.relowner <> " + oid
		sql := "SELECT coalesce(json_object_agg(n.nspname, json_build_object(" +
			"'owner', pg_get_userbyid(n.nspowner), 'owned', n.nspowner = " + oid + ", " +
			"'schema', " + privs("n.nspacl", oid) + ", " +
			"'tables', (SELECT json_agg(" + privs("t.relacl", oid) + ") FROM (" + tables + ") t), " +
			"'defaults', (SELECT coalesce(json_object_agg(pg_get_userbyid(d.defaclrole), " + privs("d.defaclacl", oid) + "), '{}'::json) FROM pg_default_acl d WHERE d.defaclnamespace = n.oid AND d.defaclobjtype = 'r')" +
			")), '{}'::json) FROM pg_namespace n WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\\_toast%' AND n.nspname NOT LIKE 'pg\\_temp\\_%';"
		out, err := runIn(ctx, r, db, sql)
		if err != nil {
			return s, err
		}
		var rows map[string]struct {
			Owner    string
			Owned    bool
			Schema   []string
			Tables   [][]string
			Defaults map[string][]string
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rows); err != nil {
			return s, fmt.Errorf("reading privileges in %s: %w", db, err)
		}
		for name, row := range rows {
			key := db + "." + name
			if row.Owned {
				s.Owned = append(s.Owned, key)
			}
			st := SchemaState{Owner: row.Owner, Schema: row.Schema, Defaults: map[string][]string{}, HasTables: len(row.Tables) > 0}
			st.Tables, st.AnyTable = intersectUnion(row.Tables)
			for who, ps := range row.Defaults {
				if len(ps) > 0 {
					st.Defaults[who] = ps
				}
			}
			s.Schemas[key] = st
		}
	}
	sort.Strings(s.Owned)
	return s, nil
}

// intersectUnion is what every list has, and what any has, each sorted.
func intersectUnion(lists [][]string) (all, any []string) {
	all, any = []string{}, []string{}
	for i, l := range lists {
		for _, p := range l {
			if !slices.Contains(any, p) {
				any = append(any, p)
			}
		}
		if i == 0 {
			all = slices.Clone(l)
			continue
		}
		all = slices.DeleteFunc(all, func(p string) bool { return !slices.Contains(l, p) })
	}
	slices.Sort(all)
	slices.Sort(any)
	return all, any
}

func sorted(l []string) []string {
	l = slices.Clone(l)
	slices.Sort(l)
	return slices.Compact(l)
}

// WithCreators fills in each schema grant's CreatedBy, where it's empty,
// with the schema's owner, as the server has it.
func (g Grants) WithCreators(s GrantsState) Grants {
	if g.Schemas == nil {
		return g
	}
	out := Grants{Databases: g.Databases, Schemas: map[string]SchemaGrant{}}
	for k, sg := range g.Schemas {
		if sg.CreatedBy == "" {
			sg.CreatedBy = s.Schemas[k].Owner
		}
		out.Schemas[k] = sg
	}
	return out
}

// SchemaDatabases returns the databases the grants read schemas in.
func (g Grants) SchemaDatabases() []string {
	var dbs []string
	for k := range g.Schemas {
		db, _, _ := SplitSchemaKey(k)
		if !slices.Contains(dbs, db) {
			dbs = append(dbs, db)
		}
	}
	slices.Sort(dbs)
	return dbs
}

// Extra lists what the server has beyond g, which applying g revokes,
// in words a plan's warning can show, and an error for a grant on an object
// the role owns, which g can't express.
func (g Grants) Extra(s GrantsState) ([]string, error) {
	var out []string
	if g.Databases != nil {
		for db := range g.Databases {
			if slices.Contains(s.Owned, db) {
				return nil, fmt.Errorf("the role owns database %s, so it has every privilege on it; leave it out of database_grants", db)
			}
		}
		for _, db := range sortedKeys(s.Databases) {
			if extra := minus(s.Databases[db], g.Databases[db]); len(extra) > 0 {
				out = append(out, strings.Join(extra, ", ")+" on database "+db)
			}
		}
	}
	if g.Schemas != nil {
		for k := range g.Schemas {
			if slices.Contains(s.Owned, k) {
				return nil, fmt.Errorf("the role owns schema %s, so it has every privilege on it; leave it out of schema_grants", k)
			}
		}
		for _, k := range sortedKeys(s.Schemas) {
			st, want := s.Schemas[k], g.Schemas[k]
			if slices.Contains(s.Owned, k) {
				continue
			}
			if extra := minus(st.Schema, want.Schema); len(extra) > 0 {
				out = append(out, strings.Join(extra, ", ")+" on schema "+k)
			}
			if extra := minus(st.AnyTable, want.Tables); len(extra) > 0 {
				out = append(out, strings.Join(extra, ", ")+" on tables in "+k)
			}
			for _, who := range sortedKeys(st.Defaults) {
				keep := want.Tables
				if who != want.CreatedBy {
					keep = nil
				}
				if extra := minus(st.Defaults[who], keep); len(extra) > 0 {
					out = append(out, strings.Join(extra, ", ")+" by default on tables "+who+" makes in "+k)
				}
			}
		}
	}
	return out, nil
}

// Matches reports whether the server has exactly g, as far as g reaches.
func (g Grants) Matches(s GrantsState) bool {
	if extra, err := g.Extra(s); err != nil || len(extra) > 0 {
		return false
	}
	for db, ps := range g.Databases {
		if !slices.Equal(sorted(ps), sorted(s.Databases[db])) {
			return false
		}
	}
	for k, want := range g.Schemas {
		st, ok := s.Schemas[k]
		if !ok {
			return false
		}
		if !slices.Equal(sorted(want.Schema), sorted(st.Schema)) {
			return false
		}
		if st.HasTables && (!slices.Equal(sorted(want.Tables), st.Tables) || !slices.Equal(st.Tables, st.AnyTable)) {
			return false
		}
		if !slices.Equal(sorted(want.Tables), sorted(st.Defaults[want.CreatedBy])) {
			return false
		}
	}
	return true
}

func minus(have, want []string) []string {
	var out []string
	for _, p := range have {
		if !slices.Contains(want, p) {
			out = append(out, p)
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func grantSQL(verb string, ps []string, on, role string) string {
	if len(ps) == 0 {
		return ""
	}
	to := " TO "
	if verb == "REVOKE" {
		to = " FROM "
	}
	return verb + " " + strings.Join(sorted(ps), ", ") + " ON " + on + to + ident(role) + ";\n"
}

// ApplyGrants makes the role's privileges match g: what isn't listed is
// revoked, then what is listed is granted, in one transaction for each
// database. Run as postgres, a REVOKE acts as the object's owner, so a
// privilege someone else granted with grant option stays, and the check
// after says so.
func ApplyGrants(ctx context.Context, r modules.Runner, role string, g Grants) (Grants, error) {
	if err := g.Validate(); err != nil {
		return g, err
	}
	s, err := ReadGrants(ctx, r, role, g.SchemaDatabases())
	if err != nil {
		return g, err
	}
	for _, k := range sortedKeys(g.Schemas) {
		if _, ok := s.Schemas[k]; !ok {
			return g, fmt.Errorf("schema %s doesn't exist", k)
		}
	}
	g = g.WithCreators(s)
	if _, err := g.Extra(s); err != nil {
		return g, err
	}
	if g.Databases != nil {
		var sql strings.Builder
		for _, db := range sortedKeys(s.Databases) {
			sql.WriteString(grantSQL("REVOKE", minus(s.Databases[db], g.Databases[db]), "DATABASE "+ident(db), role))
		}
		for _, db := range sortedKeys(g.Databases) {
			sql.WriteString(grantSQL("GRANT", minus(g.Databases[db], s.Databases[db]), "DATABASE "+ident(db), role))
		}
		if sql.Len() > 0 {
			if _, err := run(ctx, r, "BEGIN;\n"+sql.String()+"COMMIT;"); err != nil {
				return g, err
			}
		}
	}
	for _, db := range g.SchemaDatabases() {
		var sql strings.Builder
		for _, k := range sortedKeys(s.Schemas) {
			_, name, _ := SplitSchemaKey(k)
			if !strings.HasPrefix(k, db+".") || slices.Contains(s.Owned, k) {
				continue
			}
			st, want := s.Schemas[k], g.Schemas[k]
			schema := ident(name)
			// Revoke all, then grant the list: one statement each, and a
			// table added since the read is covered too.
			sql.WriteString("REVOKE ALL ON SCHEMA " + schema + " FROM " + ident(role) + ";\n")
			sql.WriteString("REVOKE ALL ON ALL TABLES IN SCHEMA " + schema + " FROM " + ident(role) + ";\n")
			for _, who := range sortedKeys(st.Defaults) {
				sql.WriteString("ALTER DEFAULT PRIVILEGES FOR ROLE " + ident(who) + " IN SCHEMA " + schema + " REVOKE ALL ON TABLES FROM " + ident(role) + ";\n")
			}
			if _, listed := g.Schemas[k]; !listed {
				continue
			}
			sql.WriteString(grantSQL("GRANT", want.Schema, "SCHEMA "+schema, role))
			sql.WriteString(grantSQL("GRANT", want.Tables, "ALL TABLES IN SCHEMA "+schema, role))
			if len(want.Tables) > 0 {
				sql.WriteString("ALTER DEFAULT PRIVILEGES FOR ROLE " + ident(want.CreatedBy) + " IN SCHEMA " + schema + " GRANT " + strings.Join(sorted(want.Tables), ", ") + " ON TABLES TO " + ident(role) + ";\n")
			}
		}
		if sql.Len() > 0 {
			if _, err := runIn(ctx, r, db, "BEGIN;\n"+sql.String()+"COMMIT;"); err != nil {
				return g, err
			}
		}
	}
	if s, err = ReadGrants(ctx, r, role, g.SchemaDatabases()); err != nil {
		return g, err
	}
	if !g.Matches(s) {
		extra, _ := g.Extra(s)
		return g, fmt.Errorf("role %s's privileges aren't as listed after the change; a privilege granted by a role other than the object's owner can only be revoked by that role: %s", role, strings.Join(extra, "; "))
	}
	return g, nil
}
