// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// server answers psql like a server with one database and one role, and
// keeps the SQL it was sent.
type server struct {
	sent  []string
	reply func(sql string) (string, string, int)
}

func (s *server) Run(_ context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	if cmd != psql {
		return ssh.Result{ExitCode: 1, Stderr: []byte("unexpected " + cmd)}, nil
	}
	sql := string(stdin)
	s.sent = append(s.sent, sql)
	out, errOut, code := s.reply(sql)
	return ssh.Result{Stdout: []byte(out), Stderr: []byte(errOut), ExitCode: code}, nil
}

// The verifier matches one computed separately, with Python's hashlib, for
// the same password, salt and iterations.
func TestVerifier(t *testing.T) {
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}
	got, err := verifier("pencil", salt, 4096)
	want := "SCRAM-SHA-256$4096:AAECAwQFBgcICQoLDA0ODw==$zHCdol2044/ZyWzPLi7oxApCkamKw9Z+E4U/QApd/5Y=:dd5peBOitVnLNFu7VmwP+HiDaaw4OUCv396eVCWhYiE="
	if err != nil || got != want {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := Verifier("pässword"); err == nil {
		t.Error("non-ASCII password hashed")
	}
	if a, _ := Verifier("x"); a == "" || a == mustVerifier(t, "x") {
		t.Error("two verifiers of one password share a salt")
	}
}

func mustVerifier(t *testing.T, p string) string {
	v, err := Verifier(p)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestValidate(t *testing.T) {
	for _, d := range []Database{{Name: ""}, {Name: strings.Repeat("a", 64)}, {Name: "a\x00"}, {Name: "app", Encoding: "UTF8; DROP"}} {
		if d.Validate() == nil {
			t.Errorf("%q passed", d.Name)
		}
	}
	if err := (Database{Name: `we"ird db`, Owner: "app", Encoding: "UTF8"}).Validate(); err != nil {
		t.Error(err)
	}
	for _, r := range []Role{{Name: "app", Attributes: []string{"LOGIN"}}, {Name: "postgres", Login: true, Attributes: []string{}}, {Name: "postgres"}} {
		if r.Validate() == nil {
			t.Errorf("%+v passed", r)
		}
	}
}

// Names and values reach the server quoted, whatever they hold, and the
// password only as a verifier.
func TestApplyRoleQuotesAndHashes(t *testing.T) {
	exists := false
	s := &server{reply: func(sql string) (string, string, int) {
		switch {
		case strings.Contains(sql, "FROM pg_roles"):
			if !exists {
				return "", "", 0
			}
			return `{"login" : true, "BYPASSRLS" : false, "CREATEDB" : true, "CREATEROLE" : false, "REPLICATION" : false, "SUPERUSER" : false}` + "\n", "", 0
		case strings.Contains(sql, "CREATE ROLE"):
			exists = true
		}
		return "", "", 0
	}}
	pw := "it's a secret"
	if err := ApplyRole(context.Background(), s, Role{Name: `o"brien`, Login: true, Attributes: []string{"CREATEDB"}}, &pw); err != nil {
		t.Fatal(err)
	}
	create := s.sent[1]
	if !strings.Contains(create, `CREATE ROLE "o""brien" WITH LOGIN NOBYPASSRLS CREATEDB NOCREATEROLE NOREPLICATION NOSUPERUSER PASSWORD 'SCRAM-SHA-256$4096:`) {
		t.Errorf("sent:\n%s", create)
	}
	for _, sql := range s.sent {
		if strings.Contains(sql, "secret") {
			t.Errorf("the password reached the server:\n%s", sql)
		}
	}
}

// A database's encoding can't change, so a different one fails with what
// to do instead of planning a change forever.
func TestApplyDatabaseEncoding(t *testing.T) {
	s := &server{reply: func(sql string) (string, string, int) {
		if strings.Contains(sql, "FROM pg_database") {
			return `{"owner" : "app", "encoding" : "SQL_ASCII"}` + "\n", "", 0
		}
		return "", "", 0
	}}
	err := ApplyDatabase(context.Background(), s, Database{Name: "app", Encoding: "UTF8"})
	if err == nil || !strings.Contains(err.Error(), "can't change a database's encoding") {
		t.Fatalf("got %v", err)
	}
	if !(Database{Name: "app", Encoding: "utf-8"}).Matches(DatabaseState{Exists: true, Encoding: "UTF8"}) {
		t.Error("utf-8 and UTF8 differ")
	}
}

// What psql says when it can't run is turned into what to do about it.
func TestRunExplainsFailures(t *testing.T) {
	for _, tc := range []struct {
		stderr string
		code   int
		want   string
	}{
		{"runuser: may not be used by non-root users", 1, "set become = true"},
		// Debian's PATH for a login other than root has no /usr/sbin.
		{"sh: 1: runuser: not found", 127, "set become = true"},
		{"runuser: failed to execute psql: No such file or directory", 127, "psql isn't installed"},
		{"runuser: user postgres does not exist", 1, "install the PostgreSQL server"},
		{`psql: error: connection to server on socket "/run/postgresql/.s.PGSQL.5432" failed`, 2, "psql: error: connection"},
	} {
		s := &server{reply: func(string) (string, string, int) { return "", tc.stderr, tc.code }}
		if _, err := ReadRole(context.Background(), s, "app"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v", tc.stderr, err)
		}
	}
}

// A database is made, given to its owner, and checked after each change.
func TestApplyDatabase(t *testing.T) {
	owner, enc, exists := "postgres", "UTF8", false
	stuck := false // ALTER DATABASE takes no effect
	s := &server{reply: func(sql string) (string, string, int) {
		switch {
		case strings.Contains(sql, "FROM pg_database"):
			if !exists {
				return "", "", 0
			}
			return `{"owner" : "` + owner + `", "encoding" : "` + enc + `"}` + "\n", "", 0
		case strings.Contains(sql, "CREATE DATABASE"):
			exists, owner = true, "app"
		case strings.Contains(sql, "ALTER DATABASE") && !stuck:
			owner = "web"
		}
		return "", "", 0
	}}
	ctx := context.Background()
	if err := ApplyDatabase(ctx, s, Database{Name: "app", Owner: "app", Encoding: "UTF8"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.sent[1], `CREATE DATABASE "app" OWNER "app" ENCODING 'UTF8' TEMPLATE template0;`) {
		t.Errorf("sent:\n%s", s.sent[1])
	}
	if err := ApplyDatabase(ctx, s, Database{Name: "app", Owner: "web"}); err != nil || !strings.Contains(s.sent[len(s.sent)-2], `ALTER DATABASE "app" OWNER TO "web";`) {
		t.Fatalf("new owner: %v", err)
	}
	stuck = true
	if err := ApplyDatabase(ctx, s, Database{Name: "app", Owner: "ops"}); err == nil || !strings.Contains(err.Error(), "isn't as set after the change: owner web") {
		t.Errorf("owner unchanged: %v", err)
	}
	if sent := len(s.sent); ApplyDatabase(ctx, s, Database{Name: ""}) == nil || len(s.sent) != sent {
		t.Error("a database with no name reached the server")
	}

	for _, name := range []string{"postgres", "template0", "template1", ""} {
		if DropDatabase(ctx, s, name) == nil {
			t.Errorf("dropped %s", name)
		}
	}
	if err := DropDatabase(ctx, s, "app"); err != nil || !strings.Contains(s.sent[len(s.sent)-1], `DROP DATABASE IF EXISTS "app";`) {
		t.Errorf("drop: %v", err)
	}
	broken := &server{reply: func(string) (string, string, int) { return "not json\n", "", 0 }}
	if _, err := ReadDatabase(ctx, broken, "app"); err == nil || !strings.Contains(err.Error(), "reading database app") {
		t.Errorf("garbled: %v", err)
	}
	if _, err := ReadRole(ctx, broken, "app"); err == nil || !strings.Contains(err.Error(), "reading role app") {
		t.Errorf("garbled role: %v", err)
	}
}

func TestApplyRoleAltersAndDrops(t *testing.T) {
	login := false
	s := &server{reply: func(sql string) (string, string, int) {
		if strings.Contains(sql, "FROM pg_roles") {
			return fmt.Sprintf(`{"login" : %t, "BYPASSRLS" : false, "CREATEDB" : false, "CREATEROLE" : false, "REPLICATION" : false, "SUPERUSER" : false}`+"\n", login), "", 0
		}
		return "", "", 0
	}}
	ctx := context.Background()
	err := ApplyRole(ctx, s, Role{Name: "app", Login: true}, nil)
	if err == nil || !strings.Contains(err.Error(), "isn't as set after the change") || !strings.Contains(s.sent[1], `ALTER ROLE "app" WITH LOGIN;`) {
		t.Errorf("unchanged: %v, sent %q", err, s.sent)
	}
	login = true
	if err := ApplyRole(ctx, s, Role{Name: "app", Login: true}, nil); err != nil {
		t.Error(err)
	}
	pw := "naïve"
	if err := ApplyRole(ctx, s, Role{Name: "app"}, &pw); err == nil || !strings.Contains(err.Error(), "printable ASCII") {
		t.Errorf("non-ASCII password: %v", err)
	}
	if DropRole(ctx, s, "postgres") == nil || DropRole(ctx, s, "") == nil {
		t.Error("dropped postgres or a role with no name")
	}
	if err := DropRole(ctx, s, "app"); err != nil || !strings.Contains(s.sent[len(s.sent)-1], `DROP ROLE IF EXISTS "app";`) {
		t.Errorf("drop: %v", err)
	}
	down := &server{reply: func(string) (string, string, int) { return "", "psql: error: connection refused", 2 }}
	if err := ApplyRole(ctx, down, Role{Name: "app"}, nil); err == nil {
		t.Error("ApplyRole with the server down")
	}
	if err := ApplyDatabase(ctx, down, Database{Name: "app"}); err == nil {
		t.Error("ApplyDatabase with the server down")
	}
}
