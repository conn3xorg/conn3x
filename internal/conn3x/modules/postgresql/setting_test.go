// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"strings"
	"testing"
)

func TestSettingMatches(t *testing.T) {
	mem8k := SettingState{Setting: "32768", Unit: "8kB", Vartype: "integer"}
	kb := SettingState{Setting: "4096", Unit: "kB", Vartype: "integer"}
	ms := SettingState{Setting: "60000", Unit: "ms", Vartype: "integer"}
	sec := SettingState{Setting: "300", Unit: "s", Vartype: "integer"}
	for name, c := range map[string]struct {
		value string
		st    SettingState
		want  bool
	}{
		"same in MB":               {"256MB", mem8k, true},
		"same in kB":               {"262144kB", mem8k, true},
		"same in GB":               {"0.25GB", mem8k, true},
		"bare number is units":     {"32768", mem8k, true},
		"different":                {"512MB", mem8k, false},
		"units are case-sensitive": {"256mb", mem8k, false},
		// 100kB is 12.5 pages: PostgreSQL rounds a half to even, to 12.
		"half to even down":   {"100kB", SettingState{Setting: "12", Unit: "8kB", Vartype: "integer"}, true},
		"half to even not up": {"100kB", SettingState{Setting: "13", Unit: "8kB", Vartype: "integer"}, false},
		"half to even up":     {"108kB", SettingState{Setting: "14", Unit: "8kB", Vartype: "integer"}, true},
		// 1.0001GB is 1024.1024MB, which guc.c makes 1024MB before anything else.
		"fraction to the smaller unit": {"1.0001GB", kb, false},
		"fraction rounded first":       {"1.0001GB", SettingState{Setting: "1048576", Unit: "kB", Vartype: "integer"}, true},
		"kB setting":                   {"4MB", kb, true},
		"time in s":                    {"60s", ms, true},
		"time in min":                  {"1min", ms, true},
		"time in min to s":             {"5min", sec, true},
		"memory unit on time":          {"60kB", ms, false},
		"unit on unitless":             {"5MB", SettingState{Setting: "100", Vartype: "integer"}, false},
		"not a number":                 {"lots", mem8k, false},
		"real":                         {"0.10", SettingState{Setting: "0.1", Vartype: "real"}, true},
		"real with unit":               {"2ms", SettingState{Setting: "2", Unit: "ms", Vartype: "real"}, true},
		"bool spellings":               {"true", SettingState{Setting: "on", Vartype: "bool"}, true},
		"bool off":                     {"no", SettingState{Setting: "on", Vartype: "bool"}, false},
		"bool nonsense":                {"maybe", SettingState{Setting: "on", Vartype: "bool"}, false},
		"enum case":                    {"Replica", SettingState{Setting: "replica", Vartype: "enum"}, true},
		"string as written":            {"UTC", SettingState{Setting: "UTC", Vartype: "string"}, true},
		"string case counts":           {"utc", SettingState{Setting: "UTC", Vartype: "string"}, false},
		"list spacing and quotes": {
			`"$user", public`, SettingState{Setting: `"$user", public`, Vartype: "string", name: "search_path"}, true,
		},
		"list without spaces": {
			"pg_stat_statements,auto_explain",
			SettingState{Setting: "pg_stat_statements, auto_explain", Vartype: "string", name: "shared_preload_libraries"}, true,
		},
		"list order counts": {
			"auto_explain, pg_stat_statements",
			SettingState{Setting: "pg_stat_statements, auto_explain", Vartype: "string", name: "shared_preload_libraries"}, false,
		},
		// Waiting for a restart, the files are what counts, not what runs.
		"pending matches the file": {
			"256MB", SettingState{Setting: "16384", Unit: "8kB", Vartype: "integer", Pending: true, File: "256MB"}, true,
		},
		"pending, file differs": {
			"256MB", SettingState{Setting: "32768", Unit: "8kB", Vartype: "integer", Pending: true, File: "128MB"}, false,
		},
	} {
		if got := (Setting{Name: "x", Value: c.value}).Matches(c.st); got != c.want {
			t.Errorf("%s: %q against %+v: %v, want %v", name, c.value, c.st, got, c.want)
		}
	}
}

func TestSettingSQL(t *testing.T) {
	for _, c := range []struct {
		s    Setting
		want string
	}{
		{Setting{"work_mem", "64MB"}, "ALTER SYSTEM SET work_mem = '64MB';"},
		{Setting{"Work_Mem", "64MB"}, "ALTER SYSTEM SET work_mem = '64MB';"},
		{Setting{"application_name", "it's"}, "ALTER SYSTEM SET application_name = 'it''s';"},
		{Setting{"pg_stat_statements.max", "5000"}, "ALTER SYSTEM SET pg_stat_statements.max = '5000';"},
		{Setting{"shared_preload_libraries", "pg_stat_statements, auto_explain"}, "ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements', 'auto_explain';"},
		{Setting{"search_path", `"$user", public`}, "ALTER SYSTEM SET search_path = '$user', 'public';"},
		{Setting{"shared_preload_libraries", ""}, "ALTER SYSTEM SET shared_preload_libraries = '';"},
	} {
		if got := settingSQL(c.s); got != c.want+"\nSELECT pg_reload_conf();" {
			t.Errorf("%+v: %q, want %q", c.s, got, c.want)
		}
	}
}

func TestSettingValidate(t *testing.T) {
	for _, s := range []Setting{
		{"", "1"}, {"work mem", "1"}, {"work_mem; drop table x", "1"}, {"a.b.c", "1"}, {"1abc", "1"},
		{strings.Repeat("x", 64), "1"}, {"work_mem", "1\n"}, {"work_mem", "a\x00"},
	} {
		if s.Validate() == nil {
			t.Errorf("%+v: no error", s)
		}
	}
	for _, s := range []Setting{{"work_mem", "64MB"}, {"pg_stat_statements.track", "all"}, {"search_path", `"$user", public`}} {
		if err := s.Validate(); err != nil {
			t.Errorf("%+v: %v", s, err)
		}
	}
}
