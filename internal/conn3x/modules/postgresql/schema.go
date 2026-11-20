// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
)

// Schema is a schema in one database. An empty Owner is left as it is, and
// a new schema without one is owned by the role that makes it, postgres.
type Schema struct {
	Name, Database, Owner string
}

// SchemaInfo is a schema as the database has it.
type SchemaInfo struct {
	Exists bool
	Owner  string
}

// Validate checks a schema before anything runs.
func (s Schema) Validate() error {
	if err := validName("schema", s.Name); err != nil {
		return err
	}
	// PostgreSQL keeps pg_ for its own schemas and refuses the rest.
	if strings.HasPrefix(s.Name, "pg_") {
		return fmt.Errorf("schema name %q starts with pg_, which PostgreSQL keeps for its own schemas", s.Name)
	}
	if err := validName("database", s.Database); err != nil {
		return err
	}
	if s.Owner != "" {
		if err := validName("owner", s.Owner); err != nil {
			return err
		}
	}
	return nil
}

// Matches reports whether the database has the schema as s wants it.
func (s Schema) Matches(st SchemaInfo) bool {
	return st.Exists && (s.Owner == "" || s.Owner == st.Owner)
}

// ReadSchema reads a schema from its database.
func ReadSchema(ctx context.Context, r modules.Runner, db, name string) (SchemaInfo, error) {
	out, err := runCmd(ctx, r, psqlIn(db), "SELECT json_build_object('owner', pg_get_userbyid(nspowner)) FROM pg_namespace WHERE nspname = "+literal(name)+";")
	if err != nil || strings.TrimSpace(out) == "" {
		return SchemaInfo{}, err
	}
	var st struct{ Owner string }
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &st); err != nil {
		return SchemaInfo{}, fmt.Errorf("reading schema %s: %w", name, err)
	}
	return SchemaInfo{Exists: true, Owner: st.Owner}, nil
}

// schemaSQL is what makes the database match s, given st.
func schemaSQL(s Schema, st SchemaInfo) []string {
	if !st.Exists {
		sql := "CREATE SCHEMA IF NOT EXISTS " + ident(s.Name)
		if s.Owner != "" {
			sql += " AUTHORIZATION " + ident(s.Owner)
		}
		return []string{sql + ";"}
	}
	if s.Owner != "" && s.Owner != st.Owner {
		return []string{"ALTER SCHEMA " + ident(s.Name) + " OWNER TO " + ident(s.Owner) + ";"}
	}
	return nil
}

// ApplySchema makes the database's schema match s.
func ApplySchema(ctx context.Context, r modules.Runner, s Schema) error {
	if err := s.Validate(); err != nil {
		return err
	}
	st, err := ReadSchema(ctx, r, s.Database, s.Name)
	if err != nil {
		return err
	}
	for _, sql := range schemaSQL(s, st) {
		if _, err := runCmd(ctx, r, psqlIn(s.Database), sql); err != nil {
			return err
		}
	}
	if st, err = ReadSchema(ctx, r, s.Database, s.Name); err != nil {
		return err
	}
	if !s.Matches(st) {
		return fmt.Errorf("schema %s isn't as set after the change: owner %s", s.Name, st.Owner)
	}
	return nil
}

// DropSchema drops a schema, if it's there. Without CASCADE, PostgreSQL
// refuses while it holds anything, and that's passed on.
func DropSchema(ctx context.Context, r modules.Runner, db, name string) error {
	if err := (Schema{Name: name, Database: db}).Validate(); err != nil {
		return err
	}
	_, err := runCmd(ctx, r, psqlIn(db), "DROP SCHEMA IF EXISTS "+ident(name)+";")
	return err
}
