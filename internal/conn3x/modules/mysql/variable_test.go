// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package mysql

import (
	"context"
	"strings"
	"testing"
)

func TestVariableValues(t *testing.T) {
	for _, c := range []struct {
		want, have string
		same       bool
	}{
		{"1G", "1073741824", true},
		{"128m", "134217728", true},
		{"500", "500", true},
		{"10", "10.000000", true},
		{"1", "ON", true},
		{"true", "ON", true},
		{"off", "OFF", true},
		{"0", "ON", false},
		{"utc", "UTC", true},
		{"2G", "1073741824", false},
		{"STRICT_TRANS_TABLES", "STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION", false},
		// #1150: the server keeps a set's members in its own order.
		{"NO_ENGINE_SUBSTITUTION,STRICT_TRANS_TABLES", "STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION", true},
		{"no_engine_substitution, strict_trans_tables", "STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION", true},
		{"STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION", "STRICT_TRANS_TABLES", false},
		// A combination mode stands for what it expands to, and is listed too.
		{"ANSI", "REAL_AS_FLOAT,PIPES_AS_CONCAT,ANSI_QUOTES,IGNORE_SPACE,ONLY_FULL_GROUP_BY,ANSI", true},
		{"TRADITIONAL", "STRICT_TRANS_TABLES,STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,TRADITIONAL,NO_ENGINE_SUBSTITUTION", true},
		{"ANSI,NO_BACKSLASH_ESCAPES", "REAL_AS_FLOAT,PIPES_AS_CONCAT,ANSI_QUOTES,IGNORE_SPACE,ONLY_FULL_GROUP_BY,NO_BACKSLASH_ESCAPES,ANSI", true},
		// A mode added by hand is still drift, and so is an empty sql_mode.
		{"ANSI", "REAL_AS_FLOAT,PIPES_AS_CONCAT,ANSI_QUOTES,IGNORE_SPACE,ONLY_FULL_GROUP_BY,ANSI,STRICT_ALL_TABLES", false},
		{"ANSI", "", false},
		{"ANSI", "REAL_AS_FLOAT,PIPES_AS_CONCAT,ANSI_QUOTES,IGNORE_SPACE,ONLY_FULL_GROUP_BY", false},
		// optimizer_switch lists every flag; only the ones named are set.
		{"mrr=on,index_merge=off", "index_merge=off,index_merge_union=on,mrr=on,mrr_cost_based=on", true},
		{"mrr=off", "index_merge=off,mrr=on", false},
	} {
		if got := sameValue(c.want, c.have); got != c.same {
			t.Errorf("sameValue(%q, %q) = %v", c.want, c.have, got)
		}
	}
	for v, want := range map[Variable]string{
		{Name: "max_connections", Value: "500"}:                              "SET GLOBAL max_connections = 500;",
		{Name: "Max_Connections", Value: "500", Mode: "persist"}:             "SET PERSIST max_connections = 500;",
		{Name: "innodb_buffer_pool_size", Value: "1G", Mode: "persist_only"}: "SET PERSIST_ONLY innodb_buffer_pool_size = 1073741824;",
		{Name: "slow_query_log", Value: "on"}:                                "SET GLOBAL slow_query_log = ON;",
		{Name: "sql_mode", Value: "STRICT_ALL_TABLES"}:                       "SET GLOBAL sql_mode = 'STRICT_ALL_TABLES';",
		{Name: "init_connect", Value: "SET NAMES 'utf8mb4'"}:                 "SET GLOBAL init_connect = 'SET NAMES ''utf8mb4''';",
		{Name: "long_query_time", Value: "0.5"}:                              "SET GLOBAL long_query_time = 0.5;",
	} {
		if got := setSQL(v); got != want {
			t.Errorf("%+v: %s, want %s", v, got, want)
		}
	}
	for _, v := range []Variable{
		{Name: "", Value: "1"}, {Name: "max connections", Value: "1"}, {Name: "a;drop", Value: "1"},
		{Name: "x", Value: "1", Mode: "session"}, {Name: "x", Value: "a\nb"}, {Name: strings.Repeat("x", 65), Value: "1"},
		{Name: "sql_mode", Value: "ORACLE"}, {Name: "SQL_MODE", Value: "postgresql,STRICT_TRANS_TABLES"},
	} {
		if v.Validate() == nil {
			t.Errorf("%+v: no error", v)
		}
	}
}

// variables is a server with system variables, and mysqld-auto.cnf when
// it's MySQL. SET takes the value it's given, or round's answer to it.
func variables(version string, running map[string]string, round func(string) string) *server {
	persisted := map[string]string{}
	return &server{reply: func(sql string) (string, string, int) {
		_, after, _ := strings.Cut(sql, "= '")
		name, _, _ := strings.Cut(after, "'")
		switch {
		case strings.Contains(sql, "SHOW GLOBAL VARIABLES"):
			if v, ok := running[name]; ok {
				return name + "\t" + v + "\n", "", 0
			}
			return "", "", 0
		case strings.Contains(sql, "SELECT VERSION()"):
			return version + "\n", "", 0
		case strings.Contains(sql, "persisted_variables"):
			if v, ok := persisted[name]; ok {
				return v + "\n", "", 0
			}
			return "", "", 0
		case strings.Contains(sql, "SET "):
			stmt := sql[strings.Index(sql, "SET "):]
			f := strings.Fields(stmt)
			verb, n, v := f[1], f[2], strings.Trim(strings.TrimSuffix(f[4], ";"), "'")
			if round != nil {
				v = round(v)
			}
			if verb != "PERSIST_ONLY" {
				running[n] = v
			}
			if verb != "GLOBAL" {
				persisted[n] = v
			}
		}
		return "", "", 0
	}}
}

func TestApplyVariable(t *testing.T) {
	ctx := context.Background()
	s := variables("8.0.40", map[string]string{"max_connections": "151"}, nil)
	v := Variable{Name: "max_connections", Value: "500", Mode: "persist"}
	if st, _ := ReadVariable(ctx, s, v.Name, v.Mode); v.Matches(st) {
		t.Fatal("matched before the change")
	}
	if err := ApplyVariable(ctx, s, v); err != nil {
		t.Fatal(err)
	}
	if st, err := ReadVariable(ctx, s, v.Name, v.Mode); err != nil || !v.Matches(st) {
		t.Errorf("after persist: %+v, %v", st, err)
	}

	// persist_only leaves the running value; global leaves mysqld-auto.cnf.
	s = variables("8.0.40", map[string]string{"innodb_buffer_pool_size": "134217728"}, nil)
	po := Variable{Name: "innodb_buffer_pool_size", Value: "1G", Mode: "persist_only"}
	if err := ApplyVariable(ctx, s, po); err != nil {
		t.Fatal(err)
	}
	if st, _ := ReadVariable(ctx, s, po.Name, po.Mode); st.Running != "134217728" || st.Persisted != "1073741824" {
		t.Errorf("after persist_only: %+v", st)
	}

	// MySQL rounds innodb_buffer_pool_size up to its chunk size.
	s = variables("8.0.40", map[string]string{"innodb_buffer_pool_size": "134217728"}, func(string) string { return "268435456" })
	err := ApplyVariable(ctx, s, Variable{Name: "innodb_buffer_pool_size", Value: "200M"})
	if err == nil || !strings.Contains(err.Error(), "took innodb_buffer_pool_size as 268435456 rather than 200M") {
		t.Errorf("a rounded value: %v", err)
	}

	// MariaDB has no SET PERSIST, and nothing is set.
	s = variables("10.11.6-MariaDB-0+deb12u1", map[string]string{"max_connections": "151"}, nil)
	if err := ApplyVariable(ctx, s, v); err == nil || !strings.Contains(err.Error(), "MariaDB has no SET PERSIST") {
		t.Errorf("persist on MariaDB: %v", err)
	}
	for _, q := range s.sent {
		if strings.Contains(q, "SET PERSIST") {
			t.Errorf("sent on MariaDB: %s", q)
		}
	}
	if err := ApplyVariable(ctx, s, Variable{Name: "max_connections", Value: "500"}); err != nil {
		t.Errorf("global on MariaDB: %v", err)
	}

	if _, err := ReadVariable(ctx, variables("8.0.40", map[string]string{}, nil), "no_such_thing", ""); err == nil || !strings.Contains(err.Error(), "no system variable no_such_thing") {
		t.Errorf("unknown variable: %v", err)
	}
}

func TestResetVariable(t *testing.T) {
	ctx := context.Background()
	for mode, want := range map[string][]string{
		"":             {"SET GLOBAL max_connections = DEFAULT;"},
		"persist":      {"SET GLOBAL max_connections = DEFAULT;", "RESET PERSIST IF EXISTS max_connections;"},
		"persist_only": {"RESET PERSIST IF EXISTS max_connections;"},
	} {
		s := variables("8.0.40", map[string]string{}, nil)
		if err := ResetVariable(ctx, s, Variable{Name: "Max_Connections", Value: "1", Mode: mode}); err != nil {
			t.Fatal(err)
		}
		for _, w := range want {
			if !strings.Contains(s.sent[0], w) {
				t.Errorf("%q: %q, want %s", mode, s.sent[0], w)
			}
		}
		if mode == "persist_only" && strings.Contains(s.sent[0], "SET GLOBAL") {
			t.Errorf("persist_only reset the running value: %s", s.sent[0])
		}
	}
}
