// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestExtensionSQL(t *testing.T) {
	for name, c := range map[string]struct {
		e    Extension
		s    ExtensionState
		want []string
	}{
		"create": {Extension{Name: "pgcrypto", Database: "app"}, ExtensionState{}, []string{`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`}},
		"create with all": {
			Extension{Name: "postgis", Database: "gis", Schema: "ext", Version: "3.4.2", Cascade: true}, ExtensionState{},
			[]string{`CREATE EXTENSION IF NOT EXISTS "postgis" SCHEMA "ext" VERSION '3.4.2' CASCADE;`},
		},
		"in line":     {Extension{Name: "x", Database: "d", Version: "1.1"}, ExtensionState{true, "public", "1.1"}, nil},
		"unset kept":  {Extension{Name: "x", Database: "d"}, ExtensionState{true, "public", "1.0"}, nil},
		"update":      {Extension{Name: "x", Database: "d", Version: "1.1"}, ExtensionState{true, "public", "1.0"}, []string{`ALTER EXTENSION "x" UPDATE TO '1.1';`}},
		"move schema": {Extension{Name: "x", Database: "d", Schema: "ext"}, ExtensionState{true, "public", "1.0"}, []string{`ALTER EXTENSION "x" SET SCHEMA "ext";`}},
		"quoting": {
			Extension{Name: `a"b`, Database: "d", Version: "1'2"}, ExtensionState{},
			[]string{`CREATE EXTENSION IF NOT EXISTS "a""b" VERSION '1''2';`},
		},
	} {
		if got := extensionSQL(c.e, c.s); !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

func TestExtensionValidate(t *testing.T) {
	for _, e := range []Extension{{Database: "d"}, {Name: "x"}, {Name: "x", Database: "d", Version: "1\n2"}, {Name: strings.Repeat("x", 64), Database: "d"}} {
		if e.Validate() == nil {
			t.Errorf("%+v accepted", e)
		}
	}
	if err := notAvailable(errors.New(`psql: ERROR:  extension "postgis" is not available`)); !strings.Contains(err.Error(), "package step") {
		t.Errorf("no hint: %v", err)
	}
}
