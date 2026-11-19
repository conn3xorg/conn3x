// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
)

// Extension is an extension in one database. An empty Schema or Version is
// left as it is, and a new extension gets the server's defaults.
type Extension struct {
	Name, Database, Schema, Version string
	// Cascade also creates the extensions this one needs.
	Cascade bool
}

// ExtensionState is an extension as the database has it.
type ExtensionState struct {
	Exists          bool
	Schema, Version string
}

// Validate checks an extension before anything runs.
func (e Extension) Validate() error {
	if err := validName("extension", e.Name); err != nil {
		return err
	}
	if err := validName("database", e.Database); err != nil {
		return err
	}
	if e.Schema != "" {
		if err := validName("schema", e.Schema); err != nil {
			return err
		}
	}
	if strings.ContainsAny(e.Version, "\x00\r\n") {
		return fmt.Errorf("version %q has a line break or NUL", e.Version)
	}
	return nil
}

// Matches reports whether the database has the extension as e wants it.
func (e Extension) Matches(s ExtensionState) bool {
	return s.Exists && (e.Schema == "" || e.Schema == s.Schema) && (e.Version == "" || e.Version == s.Version)
}

// ReadExtension reads an extension from its database.
func ReadExtension(ctx context.Context, r modules.Runner, db, name string) (ExtensionState, error) {
	out, err := runCmd(ctx, r, psqlIn(db), "SELECT json_build_object('schema', n.nspname, 'version', e.extversion) FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace WHERE e.extname = "+literal(name)+";")
	if err != nil || strings.TrimSpace(out) == "" {
		return ExtensionState{}, err
	}
	var s struct{ Schema, Version string }
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &s); err != nil {
		return ExtensionState{}, fmt.Errorf("reading extension %s: %w", name, err)
	}
	return ExtensionState{Exists: true, Schema: s.Schema, Version: s.Version}, nil
}

// extensionSQL is what makes the database match e, given s.
func extensionSQL(e Extension, s ExtensionState) []string {
	if !s.Exists {
		sql := "CREATE EXTENSION IF NOT EXISTS " + ident(e.Name)
		if e.Schema != "" {
			sql += " SCHEMA " + ident(e.Schema)
		}
		if e.Version != "" {
			sql += " VERSION " + literal(e.Version)
		}
		if e.Cascade {
			sql += " CASCADE"
		}
		return []string{sql + ";"}
	}
	var stmts []string
	if e.Version != "" && e.Version != s.Version {
		stmts = append(stmts, "ALTER EXTENSION "+ident(e.Name)+" UPDATE TO "+literal(e.Version)+";")
	}
	if e.Schema != "" && e.Schema != s.Schema {
		stmts = append(stmts, "ALTER EXTENSION "+ident(e.Name)+" SET SCHEMA "+ident(e.Schema)+";")
	}
	return stmts
}

// ApplyExtension makes the database's extension match e.
func ApplyExtension(ctx context.Context, r modules.Runner, e Extension) error {
	if err := e.Validate(); err != nil {
		return err
	}
	s, err := ReadExtension(ctx, r, e.Database, e.Name)
	if err != nil {
		return err
	}
	for _, sql := range extensionSQL(e, s) {
		if _, err := runCmd(ctx, r, psqlIn(e.Database), sql); err != nil {
			return notAvailable(err)
		}
	}
	if s, err = ReadExtension(ctx, r, e.Database, e.Name); err != nil {
		return err
	}
	if !e.Matches(s) {
		return fmt.Errorf("extension %s isn't as set after the change: schema %s, version %s", e.Name, s.Schema, s.Version)
	}
	return nil
}

// notAvailable adds the way forward to PostgreSQL's refusal of an
// extension whose files aren't installed.
func notAvailable(err error) error {
	if msg := err.Error(); strings.Contains(msg, "is not available") || strings.Contains(msg, "could not open extension control file") {
		return errors.New(msg + "; install the package that ships the extension in an earlier package step")
	}
	return err
}

// DropExtension drops an extension, if it's there. Without CASCADE,
// PostgreSQL refuses while anything depends on it, and that's passed on.
func DropExtension(ctx context.Context, r modules.Runner, db, name string) error {
	if err := (Extension{Name: name, Database: db}).Validate(); err != nil {
		return err
	}
	_, err := runCmd(ctx, r, psqlIn(db), "DROP EXTENSION IF EXISTS "+ident(name)+";")
	return err
}
