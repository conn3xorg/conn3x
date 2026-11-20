// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package mysql

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
)

// Variable is a server system variable, set with SET GLOBAL, SET PERSIST
// or SET PERSIST_ONLY.
type Variable struct {
	Name, Value string
	Mode        string // global (default), persist or persist_only
}

// VariableState is a variable as the server has it.
type VariableState struct {
	Running      string // SHOW GLOBAL VARIABLES' value
	Persisted    string // mysqld-auto.cnf's, through persisted_variables
	HasPersisted bool
}

var variableName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Validate checks a variable before anything runs.
func (v Variable) Validate() error {
	if !variableName.MatchString(v.Name) || len(v.Name) > 64 {
		return fmt.Errorf("variable name %q isn't a MySQL system variable name", v.Name)
	}
	switch v.Mode {
	case "", "global", "persist", "persist_only":
	default:
		return fmt.Errorf("mode must be global, persist or persist_only, not %q", v.Mode)
	}
	if strings.ContainsAny(v.Value, "\x00\r\n") {
		return fmt.Errorf("value for %s has a line break or NUL", v.Name)
	}
	if strings.EqualFold(v.Name, "sql_mode") {
		for m := range members(v.Value) {
			if unexpandedModes[m] {
				return fmt.Errorf("sql_mode %s is a combination mode whose members differ between server versions; give the modes it stands for instead, as SELECT @@sql_mode shows them after SET sql_mode = '%s'", m, m)
			}
		}
	}
	return nil
}

func (v Variable) mode() string {
	if v.Mode == "" {
		return "global"
	}
	return v.Mode
}

// Matches reports whether the server has the value where the mode puts
// it: running for global, in mysqld-auto.cnf for persist_only, and both
// for persist.
func (v Variable) Matches(st VariableState) bool {
	switch v.mode() {
	case "global":
		return sameValue(v.Value, st.Running)
	case "persist_only":
		return st.HasPersisted && sameValue(v.Value, st.Persisted)
	}
	return sameValue(v.Value, st.Running) && st.HasPersisted && sameValue(v.Value, st.Persisted)
}

var sizeSuffix = regexp.MustCompile(`^(?i)(\d+)([KMGT])$`)

// plain is v as SET takes it. SET has no size suffixes, unlike my.cnf, so
// 1G becomes 1073741824, which is also what the server reports back.
func plain(v string) string {
	v = strings.TrimSpace(v)
	if m := sizeSuffix.FindStringSubmatch(v); m != nil {
		n, _ := strconv.ParseUint(m[1], 10, 64)
		shift := map[string]uint{"K": 10, "M": 20, "G": 30, "T": 40}[strings.ToUpper(m[2])]
		return strconv.FormatUint(n<<shift, 10)
	}
	return v
}

var onOff = map[string]string{"1": "ON", "on": "ON", "true": "ON", "yes": "ON", "0": "OFF", "off": "OFF", "false": "OFF", "no": "OFF"}

// sameValue compares a wanted value with the server's as MySQL means them:
// a boolean the server shows as ON or OFF in any of its spellings, numbers
// as numbers (10 and 10.000000 alike), and words without case.
func sameValue(want, have string) bool {
	w, h := plain(want), strings.TrimSpace(have)
	if strings.Contains(w, ",") || strings.Contains(h, ",") {
		return sameSet(w, h)
	}
	if h == "ON" || h == "OFF" {
		if b, ok := onOff[strings.ToLower(w)]; ok {
			return b == h
		}
	}
	wf, err1 := strconv.ParseFloat(w, 64)
	hf, err2 := strconv.ParseFloat(h, 64)
	if err1 == nil && err2 == nil {
		return wf == hf
	}
	return strings.EqualFold(w, h)
}

// combinationModes are the sql_mode modes MySQL and MariaDB expand into
// others, listing the combination itself among them too. NO_AUTO_CREATE_USER
// is MariaDB's and older MySQL's; a server without it just never lists it.
var combinationModes = map[string][]string{
	"ANSI":        {"REAL_AS_FLOAT", "PIPES_AS_CONCAT", "ANSI_QUOTES", "IGNORE_SPACE", "ONLY_FULL_GROUP_BY"},
	"TRADITIONAL": {"STRICT_TRANS_TABLES", "STRICT_ALL_TABLES", "NO_ZERO_IN_DATE", "NO_ZERO_DATE", "ERROR_FOR_DIVISION_BY_ZERO", "NO_AUTO_CREATE_USER", "NO_ENGINE_SUBSTITUTION"},
}

// unexpandedModes are MariaDB's other combination modes, whose expansions
// differ between versions; Validate asks for the modes themselves instead.
var unexpandedModes = map[string]bool{"DB2": true, "MAXDB": true, "MSSQL": true, "MYSQL323": true, "MYSQL40": true, "ORACLE": true, "POSTGRESQL": true}

// members is a comma list as a set: trimmed, upper-cased, empty ones gone.
func members(v string) map[string]bool {
	m := map[string]bool{}
	for _, part := range strings.Split(v, ",") {
		if part = strings.ToUpper(strings.TrimSpace(part)); part != "" {
			m[part] = true
		}
	}
	return m
}

// sameSet compares a set-valued variable, such as sql_mode, which the
// server keeps in its own order. Members given as key=value, as in
// optimizer_switch, need only be among the server's, since it lists every
// flag and SET changes only the ones named. Otherwise the two have to hold
// the same members, where a combination mode such as ANSI also stands for
// the modes it expands to.
func sameSet(want, have string) bool {
	w, h := members(want), members(have)
	keyed := len(w) > 0
	for m := range w {
		keyed = keyed && strings.Contains(m, "=")
	}
	if keyed {
		for m := range w {
			if !h[m] {
				return false
			}
		}
		return true
	}
	allowed := map[string]bool{}
	for m := range w {
		if !h[m] {
			return false
		}
		allowed[m] = true
		for _, x := range combinationModes[m] {
			allowed[x] = true
		}
	}
	for m := range h {
		if !allowed[m] {
			return false
		}
	}
	return true
}

// sqlValue is v as SET's right-hand side: a number or ON/OFF bare, and
// anything else as a string literal.
func sqlValue(v string) string {
	p := plain(v)
	if _, err := strconv.ParseFloat(p, 64); err == nil {
		return p
	}
	if strings.EqualFold(p, "ON") || strings.EqualFold(p, "OFF") {
		return strings.ToUpper(p)
	}
	return literal(p)
}

func setSQL(v Variable) string {
	verb := map[string]string{"global": "SET GLOBAL", "persist": "SET PERSIST", "persist_only": "SET PERSIST_ONLY"}[v.mode()]
	return fmt.Sprintf("%s %s = %s;", verb, strings.ToLower(v.Name), sqlValue(v.Value))
}

// errMariaDB is what the persist modes say on MariaDB, which has no SET
// PERSIST.
var errMariaDB = errors.New("MariaDB has no SET PERSIST, so mode persist and persist_only only work on MySQL 8.0 or later; set it in a config file, such as with the circuit's settings, and restart, or use mode = \"global\", which lasts until the next restart")

// ReadVariable reads a variable, and with a persist mode, what
// mysqld-auto.cnf holds for it.
func ReadVariable(ctx context.Context, r modules.Runner, name, mode string) (VariableState, error) {
	if err := (Variable{Name: name, Mode: mode}).Validate(); err != nil {
		return VariableState{}, err
	}
	name = strings.ToLower(name)
	out, err := run(ctx, r, "SHOW GLOBAL VARIABLES WHERE Variable_name = "+literal(name)+";")
	if err != nil {
		return VariableState{}, err
	}
	_, value, ok := strings.Cut(strings.TrimRight(out, "\n"), "\t")
	if !ok {
		return VariableState{}, fmt.Errorf("the server has no system variable %s", name)
	}
	st := VariableState{Running: value}
	if mode != "persist" && mode != "persist_only" {
		return st, nil
	}
	ver, err := run(ctx, r, "SELECT VERSION();")
	if err != nil {
		return VariableState{}, err
	}
	if strings.Contains(ver, "MariaDB") {
		return VariableState{}, errMariaDB
	}
	out, err = run(ctx, r, "SELECT VARIABLE_VALUE FROM performance_schema.persisted_variables WHERE VARIABLE_NAME = "+literal(name)+";")
	if err != nil {
		return VariableState{}, err
	}
	if out != "" {
		st.Persisted, st.HasPersisted = strings.TrimRight(out, "\n"), true
	}
	return st, nil
}

// ApplyVariable sets v and reads it back. MySQL rounds some values, such
// as innodb_buffer_pool_size to its chunk size; that fails here with what
// the server chose, rather than planning a change forever.
func ApplyVariable(ctx context.Context, r modules.Runner, v Variable) error {
	if err := v.Validate(); err != nil {
		return err
	}
	if _, err := ReadVariable(ctx, r, v.Name, v.mode()); err != nil {
		return err
	}
	if _, err := run(ctx, r, setSQL(v)); err != nil {
		return err
	}
	st, err := ReadVariable(ctx, r, v.Name, v.mode())
	if err != nil {
		return err
	}
	if !v.Matches(st) {
		got := st.Running
		if v.mode() == "persist_only" {
			got = st.Persisted
		}
		return fmt.Errorf("the server took %s as %s rather than %s; MySQL rounds or caps some values, so set value to %s", v.Name, got, v.Value, got)
	}
	return nil
}

// ResetVariable undoes v: RESET PERSIST takes it out of mysqld-auto.cnf,
// and SET GLOBAL ... = DEFAULT puts the running value back to the
// default, for the modes that changed it.
func ResetVariable(ctx context.Context, r modules.Runner, v Variable) error {
	if err := v.Validate(); err != nil {
		return err
	}
	name := strings.ToLower(v.Name)
	var sql []string
	if v.mode() != "persist_only" {
		sql = append(sql, "SET GLOBAL "+name+" = DEFAULT;")
	}
	if v.mode() != "global" {
		sql = append(sql, "RESET PERSIST IF EXISTS "+name+";")
	}
	_, err := run(ctx, r, strings.Join(sql, "\n"))
	return err
}
