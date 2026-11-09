// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package postgresql manages databases and roles in a PostgreSQL server on
// the host, through psql run as the postgres user, so the controller needs
// no driver and no network path to the server.
package postgresql

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
)

// Superuser is the role psql runs as, which no step may take apart.
const Superuser = "postgres"

// psql runs SQL from stdin, so no value is ever in a command line, where
// other users on the host could read it. -X skips any .psqlrc.
const psql = "runuser -u postgres -- psql -X -q -A -t -v ON_ERROR_STOP=1 -d postgres"

// Database is a database and what's set on it. An empty Owner or Encoding
// is left as it is, and a new database gets the server's default.
type Database struct{ Name, Owner, Encoding string }

// DatabaseState is a database as the server has it.
type DatabaseState struct {
	Exists          bool
	Owner, Encoding string
}

// Attributes are the role attributes a step can set, as PostgreSQL names
// them, each with its pg_roles column.
var Attributes = map[string]string{
	"SUPERUSER": "rolsuper", "CREATEDB": "rolcreatedb", "CREATEROLE": "rolcreaterole",
	"REPLICATION": "rolreplication", "BYPASSRLS": "rolbypassrls",
}

// Role is a role. Attributes, when not nil, are exactly the ones it has;
// nil leaves them as they are.
type Role struct {
	Name       string
	Login      bool
	Attributes []string
}

// RoleState is a role as the server has it.
type RoleState struct {
	Exists     bool
	Login      bool
	Attributes []string
}

var encoding = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)

func validName(what, n string) error {
	switch {
	case n == "":
		return fmt.Errorf("%s name is empty", what)
	case len(n) > 63:
		return fmt.Errorf("%s name %q is longer than PostgreSQL's 63 bytes, so the server would cut it short", what, n)
	case strings.ContainsRune(n, 0):
		return fmt.Errorf("%s name contains NUL", what)
	}
	return nil
}

// Validate checks a database before anything runs.
func (d Database) Validate() error {
	if err := validName("database", d.Name); err != nil {
		return err
	}
	if d.Owner != "" {
		if err := validName("owner", d.Owner); err != nil {
			return err
		}
	}
	if d.Encoding != "" && !encoding.MatchString(d.Encoding) {
		return fmt.Errorf("encoding %q isn't an encoding name, such as UTF8", d.Encoding)
	}
	return nil
}

// Matches reports whether the server has the database as d wants it.
func (d Database) Matches(s DatabaseState) bool {
	return s.Exists && (d.Owner == "" || d.Owner == s.Owner) && (d.Encoding == "" || sameEncoding(d.Encoding, s.Encoding))
}

// PostgreSQL reads UTF-8 and utf8 as UTF8.
func sameEncoding(a, b string) bool {
	norm := func(s string) string { return strings.ToUpper(strings.ReplaceAll(s, "-", "")) }
	return norm(a) == norm(b)
}

// Validate checks a role before anything runs.
func (r Role) Validate() error {
	if err := validName("role", r.Name); err != nil {
		return err
	}
	for _, a := range r.Attributes {
		if Attributes[a] == "" {
			return fmt.Errorf("%q isn't a role attribute this step sets; use SUPERUSER, CREATEDB, CREATEROLE, REPLICATION or BYPASSRLS", a)
		}
	}
	if r.Name == Superuser && (!r.Login || r.Attributes != nil && !slices.Contains(r.Attributes, "SUPERUSER")) {
		return errors.New("postgres is the superuser Conn3x runs psql as; it has to keep LOGIN and SUPERUSER")
	}
	return nil
}

// Matches reports whether the server has the role as r wants it.
func (r Role) Matches(s RoleState) bool {
	if !s.Exists || r.Login != s.Login {
		return false
	}
	if r.Attributes == nil {
		return true
	}
	want := slices.Clone(r.Attributes)
	slices.Sort(want)
	return slices.Equal(slices.Compact(want), s.Attributes)
}

// ident quotes a name as an SQL identifier, and literal a value as a string.
// A literal's backslashes are plain since standard_conforming_strings, on by
// default since PostgreSQL 9.1; no string uses the E prefix.
func ident(s string) string   { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
func literal(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// run runs sql through psql and returns what it printed.
func run(ctx context.Context, r modules.Runner, sql string) (string, error) {
	// Terse errors don't quote the statement, which can hold a password's
	// verifier.
	res, err := r.Run(ctx, psql, []byte("\\set VERBOSITY terse\nSET standard_conforming_strings = on;\n"+sql+"\n"))
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(string(res.Stderr) + string(res.Stdout))
		switch {
		// runuser is in /usr/sbin, which a login other than root doesn't
		// have on its PATH on Debian and Ubuntu, so the shell can't find it.
		case strings.Contains(msg, "runuser: not found") || strings.Contains(msg, "runuser: command not found"):
			return "", errors.New("running psql as the postgres user needs root; set become = true in the ssh block")
		case res.ExitCode == 127 || strings.Contains(msg, "psql: command not found") || strings.Contains(msg, "No such file or directory") && strings.Contains(msg, "psql"):
			return "", errors.New("psql isn't installed on the host; install PostgreSQL before this step")
		case strings.Contains(msg, "may not be used by non-root users") || strings.Contains(msg, "cannot set groups"):
			return "", errors.New("running psql as the postgres user needs root; set become = true in the ssh block")
		case strings.Contains(msg, "user postgres does not exist") || strings.Contains(msg, "user postgres not found"):
			return "", errors.New("the host has no postgres user; install the PostgreSQL server before this step")
		}
		return "", fmt.Errorf("psql: %s", msg)
	}
	return string(res.Stdout), nil
}

// ReadDatabase reads a database from the server.
func ReadDatabase(ctx context.Context, r modules.Runner, name string) (DatabaseState, error) {
	out, err := run(ctx, r, "SELECT json_build_object('owner', pg_get_userbyid(datdba), 'encoding', pg_encoding_to_char(encoding)) FROM pg_database WHERE datname = "+literal(name)+";")
	if err != nil || strings.TrimSpace(out) == "" {
		return DatabaseState{}, err
	}
	var s struct{ Owner, Encoding string }
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &s); err != nil {
		return DatabaseState{}, fmt.Errorf("reading database %s: %w", name, err)
	}
	return DatabaseState{Exists: true, Owner: s.Owner, Encoding: s.Encoding}, nil
}

// ApplyDatabase makes the database match d.
func ApplyDatabase(ctx context.Context, r modules.Runner, d Database) error {
	if err := d.Validate(); err != nil {
		return err
	}
	s, err := ReadDatabase(ctx, r, d.Name)
	if err != nil {
		return err
	}
	if !s.Exists {
		sql := "CREATE DATABASE " + ident(d.Name)
		if d.Owner != "" {
			sql += " OWNER " + ident(d.Owner)
		}
		if d.Encoding != "" {
			// template1 may have another encoding; template0 takes any.
			sql += " ENCODING " + literal(d.Encoding) + " TEMPLATE template0"
		}
		if _, err := run(ctx, r, sql+";"); err != nil {
			return err
		}
	} else {
		if d.Encoding != "" && !sameEncoding(d.Encoding, s.Encoding) {
			return fmt.Errorf("database %s is %s, and PostgreSQL can't change a database's encoding; dump it, make it again with %s, and restore", d.Name, s.Encoding, d.Encoding)
		}
		if d.Owner != "" && d.Owner != s.Owner {
			if _, err := run(ctx, r, "ALTER DATABASE "+ident(d.Name)+" OWNER TO "+ident(d.Owner)+";"); err != nil {
				return err
			}
		}
	}
	if s, err = ReadDatabase(ctx, r, d.Name); err != nil {
		return err
	}
	if !d.Matches(s) {
		return fmt.Errorf("database %s isn't as set after the change: owner %s, encoding %s", d.Name, s.Owner, s.Encoding)
	}
	return nil
}

// DropDatabase drops a database, if it's there. PostgreSQL refuses while
// anyone is connected to it, and that refusal is passed on.
func DropDatabase(ctx context.Context, r modules.Runner, name string) error {
	if err := validName("database", name); err != nil {
		return err
	}
	if name == Superuser || name == "template0" || name == "template1" {
		return fmt.Errorf("%s is one of the databases the server itself needs, so Conn3x won't drop it", name)
	}
	_, err := run(ctx, r, "DROP DATABASE IF EXISTS "+ident(name)+";")
	return err
}

// ReadRole reads a role from the server.
func ReadRole(ctx context.Context, r modules.Runner, name string) (RoleState, error) {
	cols := []string{"'login', rolcanlogin"}
	for _, a := range sortedAttributes() {
		cols = append(cols, literal(a)+", "+Attributes[a])
	}
	out, err := run(ctx, r, "SELECT json_build_object("+strings.Join(cols, ", ")+") FROM pg_roles WHERE rolname = "+literal(name)+";")
	if err != nil || strings.TrimSpace(out) == "" {
		return RoleState{}, err
	}
	var row map[string]bool
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &row); err != nil {
		return RoleState{}, fmt.Errorf("reading role %s: %w", name, err)
	}
	s := RoleState{Exists: true, Login: row["login"], Attributes: []string{}}
	for _, a := range sortedAttributes() {
		if row[a] {
			s.Attributes = append(s.Attributes, a)
		}
	}
	return s, nil
}

func sortedAttributes() []string {
	out := make([]string, 0, len(Attributes))
	for a := range Attributes {
		out = append(out, a)
	}
	slices.Sort(out)
	return out
}

// ApplyRole makes the role match r, and sets its password when password
// isn't nil. The password reaches the server only as a SCRAM-SHA-256
// verifier, so it's never in the server's logs or pg_stat_activity.
func ApplyRole(ctx context.Context, h modules.Runner, r Role, password *string) error {
	if err := r.Validate(); err != nil {
		return err
	}
	var opts []string
	if r.Login {
		opts = append(opts, "LOGIN")
	} else {
		opts = append(opts, "NOLOGIN")
	}
	if r.Attributes != nil {
		for _, a := range sortedAttributes() {
			if slices.Contains(r.Attributes, a) {
				opts = append(opts, a)
			} else {
				opts = append(opts, "NO"+a)
			}
		}
	}
	if password != nil {
		v, err := Verifier(*password)
		if err != nil {
			return err
		}
		opts = append(opts, "PASSWORD "+literal(v))
	}
	s, err := ReadRole(ctx, h, r.Name)
	if err != nil {
		return err
	}
	verb := "ALTER"
	if !s.Exists {
		verb = "CREATE"
	}
	if _, err := run(ctx, h, verb+" ROLE "+ident(r.Name)+" WITH "+strings.Join(opts, " ")+";"); err != nil {
		return err
	}
	if s, err = ReadRole(ctx, h, r.Name); err != nil {
		return err
	}
	if !r.Matches(s) {
		return fmt.Errorf("role %s isn't as set after the change", r.Name)
	}
	return nil
}

// DropRole drops a role, if it's there. PostgreSQL refuses while it owns
// anything or has privileges, and that refusal is passed on.
func DropRole(ctx context.Context, r modules.Runner, name string) error {
	if err := validName("role", name); err != nil {
		return err
	}
	if name == Superuser {
		return errors.New("postgres is the superuser Conn3x runs psql as, so it won't drop it")
	}
	_, err := run(ctx, r, "DROP ROLE IF EXISTS "+ident(name)+";")
	return err
}

// Verifier is the SCRAM-SHA-256 verifier PostgreSQL stores for password,
// as in RFC 5802 and RFC 7677, with PostgreSQL's 4096 iterations. The
// server runs a password through SASLprep before checking it, which leaves
// ASCII as it is; other text is refused rather than hashed in a form a
// login might not match.
func Verifier(password string) (string, error) {
	for _, c := range password {
		if c < 0x20 || c > 0x7e {
			return "", errors.New("password_wo can only have printable ASCII characters: Conn3x hashes it before it leaves this machine, and PostgreSQL normalizes other characters in a way that isn't done here")
		}
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return verifier(password, salt, 4096)
}

func verifier(password string, salt []byte, iter int) (string, error) {
	salted, err := pbkdf2.Key(sha256.New, password, salt, iter, sha256.Size)
	if err != nil {
		return "", err
	}
	mac := func(key []byte, msg string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(msg))
		return h.Sum(nil)
	}
	stored := sha256.Sum256(mac(salted, "Client Key"))
	b := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iter, b(salt), b(stored[:]), b(mac(salted, "Server Key"))), nil
}
