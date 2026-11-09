// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"context"
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
	for stderr, want := range map[string]string{
		"runuser: may not be used by non-root users": "set become = true",
		"runuser: user postgres does not exist":      "install the PostgreSQL server",
		`psql: error: connection to server on socket "/run/postgresql/.s.PGSQL.5432" failed`: "psql: error: connection",
	} {
		s := &server{reply: func(string) (string, string, int) { return "", stderr, 1 }}
		if _, err := ReadRole(context.Background(), s, "app"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v", stderr, err)
		}
	}
}
