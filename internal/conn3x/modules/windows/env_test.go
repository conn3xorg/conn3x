// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"strings"
	"testing"
)

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

// A change, and only a change, is broadcast as WM_SETTINGCHANGE "Environment",
// with SMTO_ABORTIFHUNG and a 5 s timeout, and a failed broadcast is ignored.
// windows_path writes through the same script, so it broadcasts too.
func TestApplyEnvBroadcastsAChange(t *testing.T) {
	body := script("apply_env.ps1").Body
	noop := strings.Index(body, "if (-not $changed) { return }")
	send := strings.Index(body, `SendMessageTimeoutW(new IntPtr(0xFFFF), 0x001A, UIntPtr.Zero, "Environment", 0x0002, 5000`)
	if noop < 0 || send < 0 || send < noop {
		t.Fatalf("the broadcast must come after the no-op return: return at %d, send at %d", noop, send)
	}
	if !strings.Contains(body[send:], "} catch {") {
		t.Error("a failed broadcast must not fail the step")
	}
	for _, set := range []string{"$key.DeleteValue($A.name, $false); $changed = $true", "$key.SetValue($A.name, [string]$A.value, $kind); $changed = $true"} {
		if !strings.Contains(body, set) {
			t.Errorf("a write doesn't mark the change: %s", set)
		}
	}
	if strings.Count(body, "$changed = $true") != 2 {
		t.Error("only a delete or a write is a change")
	}
}
