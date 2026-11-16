// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// failAt passes runs to r until the nth (from 0), which fails with
// errLost as a dropped connection does.
type failAt struct {
	r modules.Runner
	n int
}

var errLost = errors.New("connection lost")

func (f *failAt) Run(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	if f.n == 0 {
		return ssh.Result{}, errLost
	}
	f.n--
	return f.r.Run(ctx, cmd, stdin)
}

// db is a server whose database changes as it's told, for read, change,
// read back.
func db(exists bool, owner string) *server {
	return &server{reply: func(sql string) (string, string, int) {
		switch {
		case strings.Contains(sql, "FROM pg_database"):
			if !exists {
				return "", "", 0
			}
			return `{"owner" : "` + owner + `", "encoding" : "UTF8"}` + "\n", "", 0
		case strings.Contains(sql, "CREATE DATABASE"):
			exists = true
		case strings.Contains(sql, "OWNER TO"):
			owner = "web"
		}
		return "", "", 0
	}}
}

// Whichever run the connection drops on, the error comes back.
func TestHostErrorsPassOn(t *testing.T) {
	ctx := context.Background()
	role := func() modules.Runner {
		exists := false
		return &server{reply: func(sql string) (string, string, int) {
			if strings.Contains(sql, "CREATE ROLE") {
				exists = true
			}
			if strings.Contains(sql, "FROM pg_roles") && exists {
				return `{"login" : true}` + "\n", "", 0
			}
			return "", "", 0
		}}
	}
	grants := func() modules.Runner {
		return &cluster{db: []string{"CREATE"}, schema: []string{}, tables: []string{"INSERT"}}
	}
	g := Grants{Databases: map[string][]string{"app": {"CONNECT"}}, Schemas: map[string]SchemaGrant{"app.public": {Schema: []string{"USAGE"}, Tables: []string{"SELECT"}}}}
	for name, c := range map[string]struct {
		host  func() modules.Runner
		apply func(modules.Runner) error
		runs  int
	}{
		"database made":    {func() modules.Runner { return db(false, "") }, func(r modules.Runner) error { return ApplyDatabase(ctx, r, Database{Name: "app"}) }, 3},
		"database owned":   {func() modules.Runner { return db(true, "app") }, func(r modules.Runner) error { return ApplyDatabase(ctx, r, Database{Name: "app", Owner: "web"}) }, 3},
		"database dropped": {func() modules.Runner { return db(true, "app") }, func(r modules.Runner) error { return DropDatabase(ctx, r, "app") }, 1},
		"role made":        {role, func(r modules.Runner) error { return ApplyRole(ctx, r, Role{Name: "app", Login: true}, nil) }, 3},
		"role dropped":     {role, func(r modules.Runner) error { return DropRole(ctx, r, "app") }, 1},
		"grants":           {grants, func(r modules.Runner) error { _, err := ApplyGrants(ctx, r, "web", g); return err }, 6},
	} {
		for n := range c.runs {
			if err := c.apply(&failAt{c.host(), n}); !errors.Is(err, errLost) {
				t.Errorf("%s, failing run %d: err = %v", name, n, err)
			}
		}
	}
}

func TestApplyDatabaseUnchanged(t *testing.T) {
	ctx := context.Background()
	// Made with the server's defaults: no OWNER, no ENCODING.
	s := db(false, "postgres")
	if err := ApplyDatabase(ctx, s, Database{Name: "app"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.sent[1], `CREATE DATABASE "app";`) {
		t.Errorf("sent:\n%s", s.sent[1])
	}
	// Already as wanted: only the reads.
	s = db(true, "web")
	if err := ApplyDatabase(ctx, s, Database{Name: "app", Owner: "web", Encoding: "utf8"}); err != nil || len(s.sent) != 2 {
		t.Errorf("in sync: %v, sent %q", err, s.sent)
	}
	if err := (Database{Name: "app", Owner: strings.Repeat("o", 64)}).Validate(); err == nil || !strings.Contains(err.Error(), "owner name") {
		t.Errorf("long owner: %v", err)
	}
}

func TestRoleMatches(t *testing.T) {
	r := Role{Name: "app", Login: true, Attributes: []string{"CREATEDB", "CREATEDB"}}
	for s, want := range map[*RoleState]bool{
		{Exists: true, Login: true, Attributes: []string{"CREATEDB"}}:              true,
		{Exists: true, Login: true, Attributes: []string{"CREATEDB", "SUPERUSER"}}: false,
		{Exists: true, Attributes: []string{"CREATEDB"}}:                           false,
		{Login: true}: false,
	} {
		if got := r.Matches(*s); got != want {
			t.Errorf("%+v: %v, want %v", *s, got, want)
		}
	}
	if !(Role{Name: "app"}).Matches(RoleState{Exists: true, Attributes: []string{"SUPERUSER"}}) {
		t.Error("nil attributes leave them as they are")
	}
	if err := (Role{Name: "postgres", Login: true, Attributes: []string{"SUPERUSER"}}).Validate(); err != nil {
		t.Errorf("postgres keeping LOGIN and SUPERUSER: %v", err)
	}
	if err := (Role{Name: "x", Attributes: []string{"SUPERUSER"}}).Validate(); err != nil {
		t.Error(err)
	}
}

// runIn uses the default psql for postgres, and names any other database.
func TestRunIn(t *testing.T) {
	ctx := context.Background()
	s := &server{reply: func(string) (string, string, int) { return "ok", "", 0 }}
	if out, err := runIn(ctx, s, "postgres", "SELECT 1;"); err != nil || out != "ok" {
		t.Errorf("postgres: %q, %v", out, err)
	}
	if got := psqlIn("it's"); got != `runuser -u postgres -- psql -X -q -A -t -v ON_ERROR_STOP=1 -d 'it'\''s'` {
		t.Errorf("psqlIn = %q", got)
	}
}

func TestGrantsMatchesEachPart(t *testing.T) {
	g := Grants{
		Databases: map[string][]string{"app": {"CONNECT"}},
		Schemas:   map[string]SchemaGrant{"app.s": {Schema: []string{"USAGE"}, Tables: []string{"SELECT"}, CreatedBy: "owner"}},
	}
	exact := func() GrantsState {
		return GrantsState{
			Databases: map[string][]string{"app": {"CONNECT"}},
			Schemas:   map[string]SchemaState{"app.s": {Schema: []string{"USAGE"}, Tables: []string{"SELECT"}, AnyTable: []string{"SELECT"}, HasTables: true, Defaults: map[string][]string{"owner": {"SELECT"}}}},
		}
	}
	if !g.Matches(exact()) {
		t.Fatal("exact doesn't match")
	}
	if g.WithCreators(exact()).Schemas["app.s"].CreatedBy != "owner" {
		t.Error("a CreatedBy that's set was replaced")
	}
	for name, change := range map[string]func(*GrantsState){
		"database lacks a privilege": func(s *GrantsState) { s.Databases = map[string][]string{} },
		"schema missing":             func(s *GrantsState) { s.Schemas = map[string]SchemaState{} },
		"schema lacks USAGE":         func(s *GrantsState) { st := s.Schemas["app.s"]; st.Schema = nil; s.Schemas["app.s"] = st },
		"a table lacks SELECT":       func(s *GrantsState) { st := s.Schemas["app.s"]; st.Tables = []string{}; s.Schemas["app.s"] = st },
		"no default": func(s *GrantsState) {
			st := s.Schemas["app.s"]
			st.Defaults = map[string][]string{}
			s.Schemas["app.s"] = st
		},
	} {
		s := exact()
		change(&s)
		if g.Matches(s) {
			t.Errorf("%s: matched", name)
		}
	}
	if (Grants{}).WithCreators(exact()).Schemas != nil {
		t.Error("no schema grants gained some")
	}
}

// Grants already in place send no change, and schema grants alone leave
// database privileges alone.
func TestApplyGrantsInSync(t *testing.T) {
	ctx := context.Background()
	c := &cluster{db: []string{"CONNECT"}}
	if _, err := ApplyGrants(ctx, c, "web", Grants{Databases: map[string][]string{"app": {"CONNECT"}}}); err != nil {
		t.Fatal(err)
	}
	if len(c.sent) != 2 {
		t.Errorf("sent %d runs, want the two reads: %q", len(c.sent), c.sent)
	}
	c = &cluster{db: []string{"CREATE"}, schema: []string{"USAGE"}, tables: []string{"INSERT"}}
	got, err := ApplyGrants(ctx, c, "web", Grants{Schemas: map[string]SchemaGrant{"app.public": {Schema: []string{"USAGE"}}}})
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(c.sent, "\n")
	if strings.Contains(all, "ON DATABASE") || strings.Contains(all, "GRANT SELECT") || !strings.Contains(all, `REVOKE ALL ON ALL TABLES IN SCHEMA "public" FROM "web";`) {
		t.Errorf("sent:\n%s", all)
	}
	if got.Schemas["app.public"].CreatedBy != "app" {
		t.Errorf("CreatedBy %q", got.Schemas["app.public"].CreatedBy)
	}
}
