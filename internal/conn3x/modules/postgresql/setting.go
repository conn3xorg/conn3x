// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
)

// Setting is a server setting as ALTER SYSTEM sets it, in
// postgresql.auto.conf.
type Setting struct {
	Name, Value string
}

// SettingState is a setting as the server has it.
type SettingState struct {
	// Setting is pg_settings.setting: the running value, in Unit for a
	// number with one.
	Setting string
	Unit    string // such as 8kB or ms, or empty
	Vartype string // bool, enum, integer, real or string
	// Pending is pending_restart: the files say something the server
	// will only use after a restart.
	Pending bool
	// File is the last value the configuration files give it, as
	// written, units and all, or empty when none does. It counts even
	// with an error: one waiting for a restart "could not be applied".
	File string

	name string // lower case, for the settings read as lists
}

// settingName is a parameter name, or a custom one with a prefix
// (pg_stat_statements.max). It goes into SQL unquoted, as ALTER SYSTEM
// takes it.
var settingName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$`)

// Validate checks a setting before anything runs.
func (s Setting) Validate() error {
	if !settingName.MatchString(s.Name) || len(s.Name) > 63 {
		return fmt.Errorf("setting name %q isn't a PostgreSQL parameter name", s.Name)
	}
	if strings.ContainsAny(s.Value, "\x00\r\n") {
		return fmt.Errorf("value for %s has a line break or NUL", s.Name)
	}
	return nil
}

// ReadSetting reads a setting from the server.
func ReadSetting(ctx context.Context, r modules.Runner, name string) (SettingState, error) {
	if err := (Setting{Name: name}).Validate(); err != nil {
		return SettingState{}, err
	}
	out, err := run(ctx, r, "SELECT json_build_object('setting', s.setting, 'unit', s.unit, 'vartype', s.vartype, 'pending', s.pending_restart, "+
		"'file', (SELECT f.setting FROM pg_file_settings f WHERE f.name = s.name ORDER BY f.seqno DESC LIMIT 1)) "+
		"FROM pg_settings s WHERE s.name = "+literal(strings.ToLower(name))+";")
	if err != nil {
		return SettingState{}, err
	}
	if strings.TrimSpace(out) == "" {
		return SettingState{}, fmt.Errorf("PostgreSQL has no setting %s", name)
	}
	var st struct {
		Setting, Unit, Vartype string
		Pending                bool
		File                   *string
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &st); err != nil {
		return SettingState{}, fmt.Errorf("reading setting %s: %w", name, err)
	}
	s := SettingState{Setting: st.Setting, Unit: st.Unit, Vartype: st.Vartype, Pending: st.Pending, name: strings.ToLower(name)}
	if st.File != nil {
		s.File = *st.File
	}
	return s, nil
}

// Matches reports whether the server has value, as PostgreSQL would read
// it: what it runs with, or while a restart is pending, what the files
// say.
func (s Setting) Matches(st SettingState) bool {
	want, ok := canonical(s.Value, st)
	if !ok {
		return false
	}
	have := st.Setting
	if st.Pending && st.File != "" {
		have = st.File
	}
	got, ok := canonical(have, st)
	return ok && want == got
}

// memory and time units, in bytes and in microseconds, as PostgreSQL
// reads them: case matters, and kB is 1024 bytes.
var memoryUnits = map[string]float64{"B": 1, "kB": 1 << 10, "MB": 1 << 20, "GB": 1 << 30, "TB": 1 << 40}
var timeUnits = map[string]float64{"us": 1, "ms": 1e3, "s": 1e6, "min": 60e6, "h": 3600e6, "d": 86400e6}

// smallerUnit is the unit below each, which guc.c's convert_to_base_unit
// rounds a fractional value to first: 30.1GB is a whole number of MB.
var smallerUnit = map[string]string{"kB": "B", "MB": "kB", "GB": "MB", "TB": "GB", "ms": "us", "s": "ms", "min": "s", "h": "min", "d": "h"}

// unitSize is how big one of a setting's units is, such as 8kB, and in
// which table.
func unitSize(unit string) (float64, map[string]float64, bool) {
	if unit == "" {
		return 1, nil, true
	}
	num, suffix := splitNumber(unit)
	n := 1.0
	if num != "" {
		v, err := strconv.ParseFloat(num, 64)
		if err != nil {
			return 0, nil, false
		}
		n = v
	}
	for _, table := range []map[string]float64{memoryUnits, timeUnits} {
		if m, ok := table[suffix]; ok {
			return n * m, table, true
		}
	}
	return 0, nil, false
}

// splitNumber splits "256MB" into "256" and "MB".
func splitNumber(v string) (string, string) {
	i := 0
	for i < len(v) && (v[i] >= '0' && v[i] <= '9' || v[i] == '.' || v[i] == '-' || v[i] == '+') {
		i++
	}
	return v[:i], strings.TrimSpace(v[i:])
}

// canonical is v as the setting st would hold it, so that two spellings
// of one value compare equal: a number in the setting's own unit, rounded
// as PostgreSQL rounds an integer (to the nearest, a half to even), a bool
// as on or off, an enum in lower case. A string is compared as written.
func canonical(v string, st SettingState) (string, bool) {
	v = strings.TrimSpace(v)
	switch st.Vartype {
	case "bool":
		switch strings.ToLower(v) {
		case "on", "true", "yes", "1", "t", "y":
			return "on", true
		case "off", "false", "no", "0", "f", "n":
			return "off", true
		}
		return "", false
	case "enum":
		return strings.ToLower(v), true
	case "integer", "real":
		num, suffix := splitNumber(v)
		n, err := strconv.ParseFloat(num, 64)
		if err != nil {
			return "", false
		}
		if suffix != "" {
			base, table, ok := unitSize(st.Unit)
			m, known := table[suffix]
			if !ok || table == nil || !known {
				return "", false
			}
			n *= m
			if sm, ok := table[smallerUnit[suffix]]; ok {
				n = math.RoundToEven(n/sm) * sm
			}
			n /= base
		}
		if st.Vartype == "integer" {
			return strconv.FormatFloat(math.RoundToEven(n), 'f', 0, 64), true
		}
		return strconv.FormatFloat(n, 'g', 15, 64), true
	default:
		if listQuoted[st.name] {
			return strings.Join(listItems(v), ","), true
		}
		return v, true
	}
}

// listQuoted are the settings PostgreSQL reads as a list of quoted names
// (GUC_LIST_QUOTE in guc_tables.c). Given as one literal, 'a, b' would be
// one name with a comma in it, so each item goes in as a literal of its
// own, and the server writes them back as "a", b.
var listQuoted = map[string]bool{
	"search_path": true, "shared_preload_libraries": true, "session_preload_libraries": true,
	"local_preload_libraries": true, "temp_tablespaces": true, "unix_socket_directories": true,
}

// listItems splits a list setting into its items, without the quotes.
func listItems(v string) []string {
	var items []string
	for _, it := range strings.Split(v, ",") {
		if it = strings.Trim(strings.TrimSpace(it), `"`); it != "" {
			items = append(items, it)
		}
	}
	return items
}

// settingSQL is what sets s, then has the server read it.
func settingSQL(s Setting) string {
	name := strings.ToLower(s.Name)
	value := literal(s.Value)
	if items := listItems(s.Value); listQuoted[name] && len(items) > 0 {
		for i, it := range items {
			items[i] = literal(it)
		}
		value = strings.Join(items, ", ")
	}
	return "ALTER SYSTEM SET " + name + " = " + value + ";\nSELECT pg_reload_conf();"
}

// ApplySetting sets s with ALTER SYSTEM, reloads, and checks the server
// took it. A setting that only takes effect after a restart is left
// pending: Conn3x doesn't restart the server.
func ApplySetting(ctx context.Context, r modules.Runner, s Setting) (SettingState, error) {
	if err := s.Validate(); err != nil {
		return SettingState{}, err
	}
	if _, err := run(ctx, r, settingSQL(s)); err != nil {
		return SettingState{}, err
	}
	// pg_reload_conf only signals the postmaster, so the server may not
	// have reread its files yet when the next query runs.
	for try := 0; ; try++ {
		st, err := ReadSetting(ctx, r, s.Name)
		if err != nil {
			return SettingState{}, err
		}
		if s.Matches(st) {
			return st, nil
		}
		if try == reloadTries {
			return st, fmt.Errorf("setting %s isn't %s after the change: the server reads %s", s.Name, s.Value, strings.TrimSpace(st.Setting+" "+st.Unit))
		}
		select {
		case <-ctx.Done():
			return st, ctx.Err()
		case <-time.After(reloadWait):
		}
	}
}

// How often, and how long apart, ApplySetting reads a setting back while
// the server reloads.
var reloadTries, reloadWait = 20, 250 * time.Millisecond

// ResetSetting takes the setting out of postgresql.auto.conf, so the
// other configuration files decide it again, and reloads.
func ResetSetting(ctx context.Context, r modules.Runner, name string) error {
	if err := (Setting{Name: name}).Validate(); err != nil {
		return err
	}
	_, err := run(ctx, r, "ALTER SYSTEM RESET "+strings.ToLower(name)+";\nSELECT pg_reload_conf();")
	return err
}
