// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package mysql

import (
	"context"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// server answers the client like a server, and keeps the SQL it was sent.
type server struct {
	sent  []string
	reply func(sql string) (string, string, int)
}

func (s *server) Run(_ context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	if cmd != client {
		return ssh.Result{ExitCode: 1, Stderr: []byte("unexpected " + cmd)}, nil
	}
	sql := string(stdin)
	if !strings.HasPrefix(sql, session) {
		return ssh.Result{ExitCode: 1, Stderr: []byte("no session settings")}, nil
	}
	s.sent = append(s.sent, sql)
	out, errOut, code := s.reply(strings.TrimPrefix(sql, session))
	return ssh.Result{Stdout: []byte(out), Stderr: []byte(errOut), ExitCode: code}, nil
}

func TestValidate(t *testing.T) {
	for _, d := range []Database{{Name: ""}, {Name: strings.Repeat("a", 65)}, {Name: "a\nb"}, {Name: "app", Charset: "utf8; DROP"}} {
		if d.Validate() == nil {
			t.Errorf("%+v passed", d)
		}
	}
	if err := (Database{Name: "we`ird db", Charset: "utf8mb4", Collation: "utf8mb4_unicode_ci"}).Validate(); err != nil {
		t.Error(err)
	}
	for _, u := range []User{
		{Name: "root", Host: "localhost"}, {Name: "mysql.sys", Host: "localhost"}, {Name: "app", Host: "local host"},
		{Name: "app", Host: "localhost", Grants: map[string][]string{"app": {"FILE"}}},
		{Name: "app", Host: "localhost", Grants: map[string][]string{"app": {}}},
		{Name: "app", Host: "localhost", Grants: map[string][]string{"app": {"ALL", "SELECT"}}},
	} {
		if u.Validate() == nil {
			t.Errorf("%+v passed", u)
		}
	}
	if err := (User{Name: "app", Host: "10.0.0.%", Grants: map[string][]string{"app": {"select", "insert"}}}).Validate(); err != nil {
		t.Error(err)
	}
	for _, p := range []string{"", "a\nb", "a\x00"} {
		if ValidPassword(p) == nil {
			t.Errorf("%q passed", p)
		}
	}
}

// A new user is made with its password and grants in one batch, every name
// and value quoted, and its grants read back from SHOW GRANTS.
func TestApplyUser(t *testing.T) {
	exists := false
	s := &server{reply: func(sql string) (string, string, int) {
		switch {
		case strings.Contains(sql, "FROM mysql.user"):
			if exists {
				return "1\n", "", 0
			}
			return "0\n", "", 0
		case strings.HasPrefix(sql, "SHOW GRANTS"):
			return "GRANT USAGE ON *.* TO `o'brien`@`localhost`\nGRANT SELECT, INSERT ON `my``db`.* TO `o'brien`@`localhost`\n", "", 0
		case strings.HasPrefix(sql, "CREATE USER"):
			exists = true
		}
		return "", "", 0
	}}
	pw := `it's \ a secret`
	u := User{Name: "o'brien", Host: "localhost", Grants: map[string][]string{"my`db": {"insert", "SELECT"}}}
	if err := ApplyUser(context.Background(), s, u, &pw); err != nil {
		t.Fatal(err)
	}
	batch := s.sent[1]
	for _, want := range []string{
		`CREATE USER 'o''brien'@'localhost' IDENTIFIED BY 'it''s \ a secret';`,
		"GRANT INSERT, SELECT ON `my``db`.* TO 'o''brien'@'localhost';",
	} {
		if !strings.Contains(batch, want) {
			t.Errorf("batch lacks %s:\n%s", want, batch)
		}
	}
	// Nothing to do once it matches.
	n := len(s.sent)
	if err := ApplyUser(context.Background(), s, u, nil); err != nil || len(s.sent) != n+2 {
		t.Errorf("second apply sent %d batches, %v", len(s.sent)-n, err)
	}
}

// Without a password, a new user would take an empty one, so it's refused.
func TestApplyUserNeedsPassword(t *testing.T) {
	s := &server{reply: func(string) (string, string, int) { return "0\n", "", 0 }}
	if err := ApplyUser(context.Background(), s, User{Name: "app", Host: "localhost"}, nil); err == nil || !strings.Contains(err.Error(), "needs password_wo") {
		t.Fatalf("got %v", err)
	}
}

// A grant on a database the step no longer lists is taken away, and one
// that changed is replaced.
func TestApplyUserRevokes(t *testing.T) {
	var sqlSent []string
	s := &server{reply: func(sql string) (string, string, int) {
		switch {
		case strings.Contains(sql, "FROM mysql.user"):
			return "1\n", "", 0
		case strings.HasPrefix(sql, "SHOW GRANTS"):
			if len(sqlSent) > 0 {
				return "GRANT ALL PRIVILEGES ON `app`.* TO `app`@`%`\n", "", 0
			}
			return "GRANT SELECT ON `app`.* TO `app`@`%`\nGRANT SELECT ON `old`.* TO `app`@`%`\n", "", 0
		}
		sqlSent = append(sqlSent, sql)
		return "", "", 0
	}}
	if err := ApplyUser(context.Background(), s, User{Name: "app", Host: "%", Grants: map[string][]string{"app": {"ALL"}}}, nil); err != nil {
		t.Fatal(err)
	}
	want := "REVOKE ALL PRIVILEGES ON `app`.* FROM 'app'@'%';\nGRANT ALL PRIVILEGES ON `app`.* TO 'app'@'%';\nREVOKE ALL PRIVILEGES ON `old`.* FROM 'app'@'%';\n"
	if len(sqlSent) != 1 || sqlSent[0] != want {
		t.Errorf("sent %q", sqlSent)
	}
}

// What the client says when it can't run is turned into what to do, and a
// syntax error never quotes the statement, which can hold a password.
func TestRunExplainsFailures(t *testing.T) {
	for stderr, want := range map[string]string{
		"ERROR 1698 (28000): Access denied for user 'root'@'localhost'":                                                                 "set become = true",
		"ERROR 2002 (HY000): Can't connect to local server through socket '/run/mysqld/mysqld.sock' (2)":                                "start it",
		"ERROR 1064 (42000) at line 2: You have an error in your SQL syntax; check the manual near 'IDENTIFIED BY 'hunter2'' at line 1": "ERROR 1064",
	} {
		s := &server{reply: func(string) (string, string, int) { return "", stderr, 1 }}
		_, err := ReadDatabase(context.Background(), s, "app")
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: got %v", stderr, err)
		}
	}
}

func TestDropDatabaseRefusesSystem(t *testing.T) {
	s := &server{reply: func(string) (string, string, int) { return "", "", 0 }}
	for _, db := range []string{"mysql", "SYS", "information_schema"} {
		if DropDatabase(context.Background(), s, db) == nil {
			t.Errorf("dropped %s", db)
		}
	}
}
