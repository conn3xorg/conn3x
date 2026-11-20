// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"slices"
	"strings"
	"testing"
)

func TestSchemaSQL(t *testing.T) {
	for name, c := range map[string]struct {
		s    Schema
		st   SchemaInfo
		want []string
	}{
		"create":            {Schema{Name: "reporting", Database: "app"}, SchemaInfo{}, []string{`CREATE SCHEMA IF NOT EXISTS "reporting";`}},
		"create with owner": {Schema{Name: "reporting", Database: "app", Owner: "app"}, SchemaInfo{}, []string{`CREATE SCHEMA IF NOT EXISTS "reporting" AUTHORIZATION "app";`}},
		"in line":           {Schema{Name: "r", Database: "d", Owner: "app"}, SchemaInfo{true, "app"}, nil},
		"owner unset kept":  {Schema{Name: "r", Database: "d"}, SchemaInfo{true, "postgres"}, nil},
		"new owner":         {Schema{Name: "r", Database: "d", Owner: "app"}, SchemaInfo{true, "postgres"}, []string{`ALTER SCHEMA "r" OWNER TO "app";`}},
		"quoting": {
			Schema{Name: `a"b`, Database: "d", Owner: `o"w`}, SchemaInfo{},
			[]string{`CREATE SCHEMA IF NOT EXISTS "a""b" AUTHORIZATION "o""w";`},
		},
	} {
		if got := schemaSQL(c.s, c.st); !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

func TestSchemaValidate(t *testing.T) {
	for want, s := range map[string]Schema{
		"schema name is empty": {Database: "d"},
		"database name":        {Name: "r"},
		"starts with pg_":      {Name: "pg_reports", Database: "d"},
		"longer than":          {Name: strings.Repeat("x", 64), Database: "d"},
		"owner name contains":  {Name: "r", Database: "d", Owner: "a\x00b"},
	} {
		if err := s.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want %q", s, err, want)
		}
	}
	if err := (Schema{Name: "reporting", Database: "app", Owner: "app"}).Validate(); err != nil {
		t.Error(err)
	}
}

func TestSchemaMatches(t *testing.T) {
	s := Schema{Name: "r", Database: "d", Owner: "app"}
	if s.Matches(SchemaInfo{}) || s.Matches(SchemaInfo{true, "postgres"}) || !s.Matches(SchemaInfo{true, "app"}) {
		t.Error("an owner that's set must match")
	}
	if !(Schema{Name: "r", Database: "d"}).Matches(SchemaInfo{true, "anyone"}) {
		t.Error("an unset owner isn't compared")
	}
}
