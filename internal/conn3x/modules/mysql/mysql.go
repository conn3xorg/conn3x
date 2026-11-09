// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package mysql manages databases and users in a MySQL or MariaDB server on
// the host, through the mysql client run as root over the server's socket,
// so the controller needs no driver and no network path to the server.
package mysql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
)

// client reads SQL from stdin, so no value is ever in a command line, where
// other users on the host could read it. -r keeps output unescaped, and the
// socket login as root is what both servers set up at install. MariaDB's
// client is mariadb, and newer ones warn that the mysql name is going away.
const client = `"$(command -v mariadb || command -v mysql)" --protocol=socket -u root -N -B -r`

// session comes first in every batch. With NO_BACKSLASH_ESCAPES a string
// literal is plain text between quotes, so doubling a quote is the only
// escaping, and the client stops reading backslashes in strings too.
const session = "SET SESSION sql_mode = CONCAT_WS(',', NULLIF(@@sql_mode, ''), 'NO_BACKSLASH_ESCAPES');\n"

// System databases the server needs, which no step drops.
var systemDatabases = []string{"mysql", "information_schema", "performance_schema", "sys"}

// Database is a database and its defaults. An empty Charset or Collation is
// left as it is, and a new database gets the server's default.
type Database struct{ Name, Charset, Collation string }

// DatabaseState is a database as the server has it.
type DatabaseState struct {
	Exists             bool
	Charset, Collation string
}

// Privileges are the privileges a database-level grant can name, as
// SHOW GRANTS prints them.
var Privileges = []string{
	"ALL PRIVILEGES", "ALTER", "ALTER ROUTINE", "CREATE", "CREATE ROUTINE", "CREATE TEMPORARY TABLES",
	"CREATE VIEW", "DELETE", "DROP", "EVENT", "EXECUTE", "INDEX", "INSERT", "LOCK TABLES",
	"REFERENCES", "SELECT", "SHOW VIEW", "TRIGGER", "UPDATE",
}

// User is an account, name@host. Grants, when not nil, are exactly its
// database-level privileges, by database; nil leaves them as they are.
type User struct {
	Name, Host string
	Grants     map[string][]string
}

// UserState is an account as the server has it.
type UserState struct {
	Exists bool
	Grants map[string][]string
}

var (
	charset = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	host    = regexp.MustCompile(`^[A-Za-z0-9._%:-]{1,255}$`)
)

func validName(what, n string, max int) error {
	switch {
	case n == "":
		return fmt.Errorf("%s name is empty", what)
	case len(n) > max:
		return fmt.Errorf("%s name %q is longer than the server's %d characters", what, n, max)
	case strings.ContainsAny(n, "\x00\n\r"):
		return fmt.Errorf("%s name contains NUL or a line break", what)
	}
	return nil
}

// Validate checks a database before anything runs.
func (d Database) Validate() error {
	if err := validName("database", d.Name, 64); err != nil {
		return err
	}
	for what, v := range map[string]string{"charset": d.Charset, "collation": d.Collation} {
		if v != "" && !charset.MatchString(v) {
			return fmt.Errorf("%s %q isn't a %s name, such as utf8mb4", what, v, what)
		}
	}
	return nil
}

// Matches reports whether the server has the database as d wants it.
func (d Database) Matches(s DatabaseState) bool {
	return s.Exists && (d.Charset == "" || strings.EqualFold(d.Charset, s.Charset)) && (d.Collation == "" || strings.EqualFold(d.Collation, s.Collation))
}

// Validate checks a user before anything runs.
func (u User) Validate() error {
	if err := validName("user", u.Name, 32); err != nil {
		return err
	}
	if !host.MatchString(u.Host) {
		return fmt.Errorf("host %q isn't a host name, address or pattern, such as localhost or 10.0.0.%%", u.Host)
	}
	if lower := strings.ToLower(u.Name); lower == "root" || strings.HasPrefix(lower, "mysql.") || strings.HasPrefix(lower, "mariadb.") {
		return fmt.Errorf("%s is an account the server itself needs, so Conn3x won't manage it", u.Name)
	}
	for db, privs := range u.Grants {
		if err := validName("database", db, 64); err != nil {
			return err
		}
		if len(privs) == 0 {
			return fmt.Errorf("the grant on %s lists no privileges; leave the database out to take its grant away", db)
		}
		for _, p := range privs {
			if !slices.Contains(Privileges, normalPrivilege(p)) {
				return fmt.Errorf("%q isn't a database privilege this step grants; use ones such as SELECT, INSERT or ALL PRIVILEGES", p)
			}
		}
		// The server prints ALL PRIVILEGES alone, so anything beside it would
		// never read back as set.
		if n := normalGrants(map[string][]string{db: privs})[db]; len(n) > 1 && slices.Contains(n, "ALL PRIVILEGES") {
			return fmt.Errorf("the grant on %s lists ALL PRIVILEGES with others; ALL PRIVILEGES already has them, so list it alone", db)
		}
	}
	return nil
}

// normalPrivilege is a privilege as SHOW GRANTS prints it.
func normalPrivilege(p string) string {
	p = strings.ToUpper(strings.Join(strings.Fields(p), " "))
	if p == "ALL" {
		return "ALL PRIVILEGES"
	}
	return p
}

func normalGrants(g map[string][]string) map[string][]string {
	out := map[string][]string{}
	for db, privs := range g {
		var ps []string
		for _, p := range privs {
			ps = append(ps, normalPrivilege(p))
		}
		slices.Sort(ps)
		out[db] = slices.Compact(ps)
	}
	return out
}

// Matches reports whether the server has the account as u wants it.
func (u User) Matches(s UserState) bool {
	if !s.Exists {
		return false
	}
	if u.Grants == nil {
		return true
	}
	want, got := normalGrants(u.Grants), normalGrants(s.Grants)
	if len(want) != len(got) {
		return false
	}
	for db, p := range want {
		if !slices.Equal(p, got[db]) {
			return false
		}
	}
	return true
}

// ident quotes a name as an identifier, and literal a value as a string,
// which session makes free of backslash escapes.
func ident(s string) string   { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }
func literal(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func account(u User) string { return literal(u.Name) + "@" + literal(u.Host) }

// near is the part of a syntax error that quotes the statement, which can
// hold a password.
var near = regexp.MustCompile(`(?s) near '.*`)

// run runs sql through the client and returns what it printed.
func run(ctx context.Context, r modules.Runner, sql string) (string, error) {
	res, err := r.Run(ctx, client, []byte(session+sql+"\n"))
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		msg := near.ReplaceAllString(strings.TrimSpace(string(res.Stderr)+string(res.Stdout)), "")
		switch {
		case res.ExitCode == 127:
			return "", errors.New("the mysql client isn't installed on the host; install MySQL or MariaDB before this step")
		case strings.Contains(msg, "Access denied for user 'root'"):
			return "", errors.New("the server refused root over its socket; Conn3x logs in as root the way the server is set up at install, so set become = true in the ssh block, and keep root's socket login")
		case strings.Contains(msg, "Can't connect to local") || strings.Contains(msg, "Can't connect to server"):
			return "", errors.New("the server isn't answering on its socket; start it before this step")
		}
		return "", fmt.Errorf("mysql: %s", msg)
	}
	return string(res.Stdout), nil
}

// ReadDatabase reads a database from the server.
func ReadDatabase(ctx context.Context, r modules.Runner, name string) (DatabaseState, error) {
	out, err := run(ctx, r, "SELECT JSON_OBJECT('charset', DEFAULT_CHARACTER_SET_NAME, 'collation', DEFAULT_COLLATION_NAME) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = "+literal(name)+";")
	if err != nil || strings.TrimSpace(out) == "" {
		return DatabaseState{}, err
	}
	var s struct{ Charset, Collation string }
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &s); err != nil {
		return DatabaseState{}, fmt.Errorf("reading database %s: %w", name, err)
	}
	return DatabaseState{Exists: true, Charset: s.Charset, Collation: s.Collation}, nil
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
	opts := ""
	if d.Charset != "" {
		opts += " CHARACTER SET " + d.Charset
	}
	if d.Collation != "" {
		opts += " COLLATE " + d.Collation
	}
	switch {
	case !s.Exists:
		_, err = run(ctx, r, "CREATE DATABASE "+ident(d.Name)+opts+";")
	case !d.Matches(s):
		// Only the defaults for new tables change; existing ones keep theirs.
		_, err = run(ctx, r, "ALTER DATABASE "+ident(d.Name)+opts+";")
	}
	if err != nil {
		return err
	}
	if s, err = ReadDatabase(ctx, r, d.Name); err != nil {
		return err
	}
	if !d.Matches(s) {
		return fmt.Errorf("database %s isn't as set after the change: charset %s, collation %s", d.Name, s.Charset, s.Collation)
	}
	return nil
}

// DropDatabase drops a database and everything in it, if it's there.
func DropDatabase(ctx context.Context, r modules.Runner, name string) error {
	if err := validName("database", name, 64); err != nil {
		return err
	}
	if slices.Contains(systemDatabases, strings.ToLower(name)) {
		return fmt.Errorf("%s is a database the server itself needs, so Conn3x won't drop it", name)
	}
	_, err := run(ctx, r, "DROP DATABASE IF EXISTS "+ident(name)+";")
	return err
}

// grantLine is one database-level line of SHOW GRANTS, such as
// GRANT SELECT, INSERT ON `app`.* TO `app`@`localhost`.
var grantLine = regexp.MustCompile("^GRANT (.+?) ON `((?:[^`]|``)+)`\\.\\* TO ")

// ReadUser reads an account and its database-level grants.
func ReadUser(ctx context.Context, r modules.Runner, u User) (UserState, error) {
	out, err := run(ctx, r, "SELECT COUNT(*) FROM mysql.user WHERE User = "+literal(u.Name)+" AND Host = "+literal(u.Host)+";")
	if err != nil {
		return UserState{}, err
	}
	if strings.TrimSpace(out) == "0" {
		return UserState{}, nil
	}
	if out, err = run(ctx, r, "SHOW GRANTS FOR "+account(u)+";"); err != nil {
		return UserState{}, err
	}
	s := UserState{Exists: true, Grants: map[string][]string{}}
	for _, line := range strings.Split(out, "\n") {
		m := grantLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		db := strings.ReplaceAll(m[2], "``", "`")
		for _, p := range strings.Split(m[1], ",") {
			s.Grants[db] = append(s.Grants[db], normalPrivilege(p))
		}
	}
	return s, nil
}

// ApplyUser makes the account match u, and sets its password when password
// isn't nil. A new account needs one: with none, the server lets anyone log
// in as it with an empty password. The password goes to the server on
// stdin, inside the statement, so the server sees it in plain text.
func ApplyUser(ctx context.Context, r modules.Runner, u User, password *string) error {
	if err := u.Validate(); err != nil {
		return err
	}
	if password != nil {
		if err := ValidPassword(*password); err != nil {
			return err
		}
	}
	s, err := ReadUser(ctx, r, u)
	if err != nil {
		return err
	}
	var sql []string
	switch {
	case !s.Exists && password == nil:
		return fmt.Errorf("user %s@%s doesn't exist, and a new one needs password_wo: without one the server lets anyone log in as it with no password", u.Name, u.Host)
	case !s.Exists:
		sql = append(sql, "CREATE USER "+account(u)+" IDENTIFIED BY "+literal(*password)+";")
	case password != nil:
		sql = append(sql, "ALTER USER "+account(u)+" IDENTIFIED BY "+literal(*password)+";")
	}
	if u.Grants != nil && !u.Matches(UserState{Exists: true, Grants: s.Grants}) {
		want, got := normalGrants(u.Grants), normalGrants(s.Grants)
		dbs := make([]string, 0, len(got)+len(want))
		for db := range got {
			dbs = append(dbs, db)
		}
		for db := range want {
			dbs = append(dbs, db)
		}
		slices.Sort(dbs)
		for _, db := range slices.Compact(dbs) {
			if slices.Equal(want[db], got[db]) {
				continue
			}
			if got[db] != nil {
				sql = append(sql, "REVOKE ALL PRIVILEGES ON "+ident(db)+".* FROM "+account(u)+";")
			}
			if want[db] != nil {
				sql = append(sql, "GRANT "+strings.Join(want[db], ", ")+" ON "+ident(db)+".* TO "+account(u)+";")
			}
		}
	}
	if len(sql) == 0 {
		return nil
	}
	if _, err := run(ctx, r, strings.Join(sql, "\n")); err != nil {
		return err
	}
	if s, err = ReadUser(ctx, r, u); err != nil {
		return err
	}
	if !u.Matches(s) {
		return fmt.Errorf("user %s@%s isn't as set after the change", u.Name, u.Host)
	}
	return nil
}

// DropUser drops an account, if it's there.
func DropUser(ctx context.Context, r modules.Runner, u User) error {
	if err := u.Validate(); err != nil {
		return err
	}
	_, err := run(ctx, r, "DROP USER IF EXISTS "+account(u)+";")
	return err
}

// ValidPassword checks a password can go into a statement as a literal: any
// text but NUL and line breaks, which would end the client's line.
func ValidPassword(p string) error {
	switch {
	case p == "":
		return errors.New("password_wo must not be empty")
	case strings.ContainsAny(p, "\x00\n\r"):
		return errors.New("password_wo must not contain NUL or a line break")
	}
	return nil
}
