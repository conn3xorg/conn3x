// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package mysql

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// schemata is a server with at most one database, whose charset and
// collation change as it's told unless stuck.
func schemata(exists bool, charset, collation string, stuck bool) *server {
	return &server{reply: func(sql string) (string, string, int) {
		switch {
		case strings.Contains(sql, "information_schema.SCHEMATA"):
			if !exists {
				return "", "", 0
			}
			return `{"charset": "` + charset + `", "collation": "` + collation + `"}` + "\n", "", 0
		case strings.HasPrefix(sql, "CREATE DATABASE"), strings.HasPrefix(sql, "ALTER DATABASE"):
			if stuck {
				return "", "", 0
			}
			exists = true
			if _, cs, ok := strings.Cut(sql, " CHARACTER SET "); ok {
				charset, _, _ = strings.Cut(cs, " ")
				charset = strings.TrimSuffix(strings.TrimSpace(charset), ";")
			}
			if _, co, ok := strings.Cut(sql, " COLLATE "); ok {
				collation = strings.TrimSuffix(strings.TrimSpace(co), ";")
			}
		}
		return "", "", 0
	}}
}

func TestApplyDatabase(t *testing.T) {
	ctx := context.Background()
	d := Database{Name: "app", Charset: "utf8mb4", Collation: "utf8mb4_bin"}

	s := schemata(false, "", "", false)
	if err := ApplyDatabase(ctx, s, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.sent[1], "CREATE DATABASE `app` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;") {
		t.Errorf("create: %s", s.sent[1])
	}

	// Another collation: only the defaults change.
	s = schemata(true, "utf8mb4", "utf8mb4_general_ci", false)
	if err := ApplyDatabase(ctx, s, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.sent[1], "ALTER DATABASE `app` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;") {
		t.Errorf("alter: %s", s.sent[1])
	}

	// As wanted, in another case: the reads alone.
	s = schemata(true, "UTF8MB4", "UTF8MB4_BIN", false)
	if err := ApplyDatabase(ctx, s, d); err != nil || len(s.sent) != 2 {
		t.Errorf("in sync: %v, sent %q", err, s.sent)
	}
	// No charset or collation asked for: any will do, and none is sent.
	s = schemata(false, "latin1", "latin1_swedish_ci", false)
	if err := ApplyDatabase(ctx, s, Database{Name: "app"}); err != nil || !strings.Contains(s.sent[1], "CREATE DATABASE `app`;") {
		t.Errorf("defaults: %v, sent %q", err, s.sent)
	}

	s = schemata(true, "latin1", "latin1_swedish_ci", true)
	if err := ApplyDatabase(ctx, s, d); err == nil || err.Error() != "database app isn't as set after the change: charset latin1, collation latin1_swedish_ci" {
		t.Errorf("stuck: %v", err)
	}
	s = schemata(false, "", "", false)
	if err := ApplyDatabase(ctx, s, Database{Name: ""}); err == nil || len(s.sent) != 0 {
		t.Errorf("invalid: %v, sent %q", err, s.sent)
	}
	garbled := &server{reply: func(string) (string, string, int) { return "nope\n", "", 0 }}
	if _, err := ReadDatabase(ctx, garbled, "app"); err == nil || !strings.HasPrefix(err.Error(), "reading database app: ") {
		t.Errorf("garbled: %v", err)
	}
	if err := DropDatabase(ctx, s, "app"); err != nil || !strings.Contains(s.sent[len(s.sent)-1], "DROP DATABASE IF EXISTS `app`;") {
		t.Errorf("drop: %v", err)
	}
	if err := DropDatabase(ctx, s, ""); err == nil {
		t.Error("dropped a database with no name")
	}
}

func TestUserMatches(t *testing.T) {
	u := User{Name: "app", Host: "%", Grants: map[string][]string{"app": {"select"}}}
	for name, c := range map[string]struct {
		s    UserState
		want bool
	}{
		"missing":       {UserState{}, false},
		"same":          {UserState{Exists: true, Grants: map[string][]string{"app": {"SELECT"}}}, true},
		"another db":    {UserState{Exists: true, Grants: map[string][]string{"app": {"SELECT"}, "old": {"SELECT"}}}, false},
		"other grant":   {UserState{Exists: true, Grants: map[string][]string{"app": {"INSERT"}}}, false},
		"other db only": {UserState{Exists: true, Grants: map[string][]string{"old": {"SELECT"}}}, false},
	} {
		if got := u.Matches(c.s); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
	if !(User{Name: "app", Host: "%"}).Matches(UserState{Exists: true, Grants: map[string][]string{"x": {"ALL PRIVILEGES"}}}) {
		t.Error("nil grants leave them as they are")
	}
}

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

func TestHostErrorsPassOn(t *testing.T) {
	ctx := context.Background()
	user := func() modules.Runner {
		return &server{reply: func(sql string) (string, string, int) {
			if strings.Contains(sql, "FROM mysql.user") {
				return "1\n", "", 0
			}
			return "", "", 0
		}}
	}
	pw := "secret"
	for name, c := range map[string]struct {
		host  func() modules.Runner
		apply func(modules.Runner) error
		runs  int
	}{
		"database":  {func() modules.Runner { return schemata(false, "", "", false) }, func(r modules.Runner) error { return ApplyDatabase(ctx, r, Database{Name: "app"}) }, 3},
		"drop":      {func() modules.Runner { return schemata(true, "", "", false) }, func(r modules.Runner) error { return DropDatabase(ctx, r, "app") }, 1},
		"user":      {user, func(r modules.Runner) error { return ApplyUser(ctx, r, User{Name: "app", Host: "%"}, &pw) }, 5},
		"drop user": {user, func(r modules.Runner) error { return DropUser(ctx, r, User{Name: "app", Host: "%"}) }, 1},
	} {
		for n := range c.runs {
			if err := c.apply(&failAt{c.host(), n}); !errors.Is(err, errLost) {
				t.Errorf("%s, failing run %d: err = %v", name, n, err)
			}
		}
	}
}

func TestApplyUserPasswordAndDrop(t *testing.T) {
	ctx := context.Background()
	var sent []string
	s := &server{reply: func(sql string) (string, string, int) {
		switch {
		case strings.Contains(sql, "FROM mysql.user"):
			return "1\n", "", 0
		case strings.HasPrefix(sql, "SHOW GRANTS"):
			return "GRANT USAGE ON *.* TO `app`@`%`\n", "", 0
		}
		sent = append(sent, sql)
		return "", "", 0
	}}
	pw := "n3w"
	if err := ApplyUser(ctx, s, User{Name: "app", Host: "%"}, &pw); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || sent[0] != "ALTER USER 'app'@'%' IDENTIFIED BY 'n3w';\n" {
		t.Errorf("sent %q", sent)
	}
	bad := "a\nb"
	if err := ApplyUser(ctx, s, User{Name: "app", Host: "%"}, &bad); err == nil || len(sent) != 1 {
		t.Errorf("a password with a line break: %v", err)
	}
	if err := ApplyUser(ctx, s, User{Name: "root", Host: "%"}, nil); err == nil {
		t.Error("managed root")
	}
	// The grants read back short of what was asked.
	if err := ApplyUser(ctx, s, User{Name: "app", Host: "%", Grants: map[string][]string{"app": {"SELECT"}}}, nil); err == nil || err.Error() != "user app@% isn't as set after the change" {
		t.Errorf("read back: %v", err)
	}
	if err := DropUser(ctx, s, User{Name: "app", Host: "%"}); err != nil || sent[len(sent)-1] != "DROP USER IF EXISTS 'app'@'%';\n" {
		t.Errorf("drop: %v, sent %q", err, sent)
	}
	if err := DropUser(ctx, s, User{Name: "mysql.sys", Host: "localhost"}); err == nil {
		t.Error("dropped mysql.sys")
	}
	if _, err := run(ctx, &server{reply: func(string) (string, string, int) { return "", "", 127 }}, "SELECT 1;"); err == nil || !strings.Contains(err.Error(), "client isn't installed") {
		t.Errorf("no client: %v", err)
	}
}
