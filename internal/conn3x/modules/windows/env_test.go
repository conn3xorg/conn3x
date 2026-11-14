// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import "testing"

func TestPathEntry(t *testing.T) {
	const path = `%SystemRoot%\system32;%SystemRoot%;C:\Tools\;C:\Program Files\Git\cmd`
	add := PathEntry{Element: `C:\Go\bin`}
	if add.Matches(ActualEnv{Exists: true, Value: path}) {
		t.Error("matched before it's there")
	}
	if got := add.NewPath(path); got != path+`;C:\Go\bin` {
		t.Errorf("add: %q", got)
	}
	// The same folder, another case or trailing backslash: already there.
	same := PathEntry{Element: `c:\tools`}
	if !same.Matches(ActualEnv{Exists: true, Value: path}) || same.NewPath(path) != path {
		t.Error(`c:\tools isn't C:\Tools\`)
	}
	rm := PathEntry{Element: `C:\Tools`, Absent: true}
	if got := rm.NewPath(path + `;C:\TOOLS`); got != `%SystemRoot%\system32;%SystemRoot%;C:\Program Files\Git\cmd` {
		t.Errorf("remove every copy: %q", got)
	}
	if !rm.Matches(ActualEnv{Exists: true, Value: `%SystemRoot%`}) || !rm.Matches(ActualEnv{}) {
		t.Error("absent")
	}
	if got := add.NewPath(""); got != `C:\Go\bin` {
		t.Errorf("empty Path: %q", got)
	}
	if got := add.NewPath(`C:\A;`); got != `C:\A;C:\Go\bin` {
		t.Errorf("trailing ;: %q", got)
	}
	for _, bad := range []string{"", " ", `C:\a;C:\b`, `C:\"x"`} {
		if (PathEntry{Element: bad}).Validate() == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestEnvVar(t *testing.T) {
	e := EnvVar{Name: "JAVA_HOME", Value: `C:\Java\jdk-21`}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	if !e.Matches(ActualEnv{Exists: true, Value: `C:\Java\jdk-21`}) || e.Matches(ActualEnv{Exists: true, Value: `C:\Java\jdk-17`}) || e.Matches(ActualEnv{}) {
		t.Error("matches")
	}
	if !(EnvVar{Name: "X", Absent: true}).Matches(ActualEnv{}) {
		t.Error("absent")
	}
	for _, bad := range []EnvVar{{}, {Name: "A=B"}, {Name: "X", Value: "a\x00b"}} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
