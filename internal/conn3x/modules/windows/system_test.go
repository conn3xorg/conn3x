// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func ok(v any) map[string]any { return map[string]any{"ok": true, "value": v} }

// args is what the fake's i-th run sent to the script.
func args(f *fake, i int) map[string]any { return f.sent[i]["args"].(map[string]any) }

func TestRegistryValidate(t *testing.T) {
	for _, v := range []RegistryValue{
		{Key: `HKLM\SOFTWARE\App`, Type: "string"},
		{Key: `HKEY_LOCAL_MACHINE\SOFTWARE\App`, Name: "Level", Type: "dword"},
	} {
		if err := v.Validate(); err != nil {
			t.Errorf("%+v: %v", v, err)
		}
	}
	for want, v := range map[string]RegistryValue{
		"must be under HKLM":     {Key: `HKCU\Software`, Type: "string"},
		"empty or relative part": {Key: `HKLM\SOFTWARE\..\SAM`, Type: "string"},
		"empty or relative":      {Key: `HKLM\SOFTWARE\\App`, Type: "string"},
		"value name":             {Key: `HKLM\SOFTWARE\App`, Name: "a\nb", Type: "string"},
		"value name \"":          {Key: `HKLM\SOFTWARE\App`, Name: strings.Repeat("n", 16384), Type: "string"},
		`must be "string"`:       {Key: `HKLM\SOFTWARE\App`, Type: "none"},
	} {
		if err := v.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want %q", v.Key, err, want)
		}
	}
}

// Data is put in one form to compare, and errors never quote it.
func TestRegistryCanonical(t *testing.T) {
	for _, c := range []struct{ typ, data, want string }{
		{"dword", "007", "7"},
		{"qword", "18446744073709551615", "18446744073709551615"},
		{"binary", "0AFF", "0aff"},
		{"multi_string", "a\nb\n", "a\nb"},
		{"string", "plain", "plain"},
		{"expand_string", "%SystemRoot%", "%SystemRoot%"},
	} {
		v := RegistryValue{Key: `HKLM\S`, Type: c.typ, Data: c.data}
		if got, err := v.Canonical(); err != nil || got != c.want {
			t.Errorf("%s %q: %q, %v", c.typ, c.data, got, err)
		}
	}
	for _, c := range []struct{ typ, data, want string }{
		{"dword", "4294967296", "up to 4294967295"},
		{"qword", "-1", "must be a decimal number"},
		{"binary", "xyz", "must be hex"},
		{"multi_string", "a\r\nb", "no NUL or carriage return"},
		{"multi_string", "a\x00", "no NUL"},
		{"string", "s3cret\x00", "must not contain NUL"},
	} {
		err := RegistryValue{Type: c.typ, Data: c.data}.CheckData()
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), c.data) {
			t.Errorf("%s %q: %v, want %q without the data", c.typ, c.data, err, c.want)
		}
	}
}

func TestReadRegistry(t *testing.T) {
	ctx := context.Background()
	v := RegistryValue{Key: `HKLM\SOFTWARE\App`, Name: "x"}
	for name, c := range map[string]struct {
		answer map[string]any
		want   ActualRegistry
	}{
		"missing": {ok(map[string]any{"exists": false}), ActualRegistry{}},
		// .NET reports a dword's bits signed.
		"dword":        {ok(map[string]any{"exists": true, "kind": "DWord", "data": "-1"}), ActualRegistry{Exists: true, Type: "dword", Data: "4294967295"}},
		"qword":        {ok(map[string]any{"exists": true, "kind": "QWord", "data": "-2"}), ActualRegistry{Exists: true, Type: "qword", Data: "18446744073709551614"}},
		"binary":       {ok(map[string]any{"exists": true, "kind": "Binary", "data": "Cv8="}), ActualRegistry{Exists: true, Type: "binary", Data: "0aff"}},
		"multi_string": {ok(map[string]any{"exists": true, "kind": "MultiString", "data": []string{"a", "b"}}), ActualRegistry{Exists: true, Type: "multi_string", Data: "a\nb"}},
		"string":       {ok(map[string]any{"exists": true, "kind": "String", "data": "v", "sha256": "ab"}), ActualRegistry{Exists: true, Type: "string", Data: "v", SHA256: "ab"}},
		// A kind this module doesn't write can't match anything.
		"REG_NONE": {ok(map[string]any{"exists": true, "kind": "None", "data": 5}), ActualRegistry{Exists: true}},
	} {
		got, err := ReadRegistry(ctx, &fake{answers: []map[string]any{c.answer}}, v, false)
		if err != nil || got != c.want {
			t.Errorf("%s: %+v, %v; want %+v", name, got, err, c.want)
		}
	}

	f := &fake{answers: []map[string]any{ok(map[string]any{"exists": true, "kind": "String", "sha256": "ab"})}}
	if got, err := ReadRegistry(ctx, f, v, true); err != nil || got.Data != "" || got.SHA256 != "ab" || args(f, 0)["hash_only"] != true || args(f, 0)["key"] != `SOFTWARE\App` {
		t.Errorf("hash only: %+v, %v, sent %v", got, err, f.sent[0])
	}

	for name, a := range map[string]map[string]any{
		"not an object":    ok("x"),
		"multi not a list": ok(map[string]any{"exists": true, "kind": "MultiString", "data": "a"}),
		"string not text":  ok(map[string]any{"exists": true, "kind": "String", "data": 1}),
		"dword not number": ok(map[string]any{"exists": true, "kind": "DWord", "data": "x"}),
		"qword not number": ok(map[string]any{"exists": true, "kind": "QWord", "data": "x"}),
		"binary not b64":   ok(map[string]any{"exists": true, "kind": "Binary", "data": "!!"}),
	} {
		if _, err := ReadRegistry(ctx, &fake{answers: []map[string]any{a}}, v, false); err == nil || err.Error() != "reading a registry value: the host's answer wasn't valid" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ReadRegistry(ctx, &fake{answers: []map[string]any{{"ok": false, "error": "denied"}}}, v, false); err == nil || err.Error() != "denied" {
		t.Errorf("host error: %v", err)
	}
	if _, err := ReadRegistry(ctx, &fake{}, RegistryValue{Key: "HKCU"}, false); err == nil {
		t.Error("read outside HKLM")
	}
}

func TestRegistryMatches(t *testing.T) {
	v := RegistryValue{Key: `HKLM\S`, Type: "dword", Data: "01"}
	if m, err := v.Matches(ActualRegistry{Exists: true, Type: "dword", Data: "1"}); !m || err != nil {
		t.Errorf("same number: %v, %v", m, err)
	}
	for _, a := range []ActualRegistry{{}, {Exists: true, Type: "qword", Data: "1"}, {Exists: true, Type: "dword", Data: "2"}} {
		if m, _ := v.Matches(a); m {
			t.Errorf("matched %+v", a)
		}
	}
	if _, err := (RegistryValue{Type: "dword", Data: "x"}).Matches(ActualRegistry{}); err == nil {
		t.Error("bad data matched")
	}
}

func TestApplyRegistry(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		typ, data string
		wire      any
	}{
		{"binary", "0aff", "Cv8="},
		{"multi_string", "a\nb", []any{"a", "b"}},
		{"dword", "08", "8"},
	} {
		f := &fake{answers: []map[string]any{ok(nil)}}
		if err := ApplyRegistry(ctx, f, RegistryValue{Key: `HKLM\S\App`, Name: "n", Type: c.typ, Data: c.data}); err != nil {
			t.Fatal(err)
		}
		s := args(f, 0)
		if s["key"] != `S\App` || s["kind"] != registryKinds[c.typ] || !equalJSON(s["data"], c.wire) {
			t.Errorf("%s sent %v", c.typ, s)
		}
	}
	// What the host says back has the data blanked.
	f := &fake{answers: []map[string]any{{"ok": false, "error": "can't write s3cret"}}}
	err := ApplyRegistry(ctx, f, RegistryValue{Key: `HKLM\S`, Type: "string", Data: "s3cret"})
	if err == nil || strings.Contains(err.Error(), "s3cret") || !strings.Contains(err.Error(), "can't write") {
		t.Errorf("got %v", err)
	}
	f = &fake{}
	if ApplyRegistry(ctx, f, RegistryValue{Key: "HKCU", Type: "string"}) == nil || ApplyRegistry(ctx, f, RegistryValue{Key: `HKLM\S`, Type: "dword", Data: "x"}) == nil || len(f.sent) != 0 {
		t.Error("an invalid value reached the host")
	}

	f = &fake{answers: []map[string]any{ok(nil)}}
	if err := ApplyRegistryRemove(ctx, f, RegistryValue{Key: `HKLM\S`, Name: "n"}); err != nil || args(f, 0)["key"] != "S" || args(f, 0)["name"] != "n" {
		t.Errorf("remove: %v, sent %v", err, f.sent)
	}
	if ApplyRegistryRemove(ctx, &fake{}, RegistryValue{Key: `HKLM\.`}) == nil {
		t.Error("removed under a relative key")
	}
}

func equalJSON(a, b any) bool {
	as, aok := a.([]any)
	bs, bok := b.([]any)
	if aok && bok {
		if len(as) != len(bs) {
			return false
		}
		for i := range as {
			if as[i] != bs[i] {
				return false
			}
		}
		return true
	}
	return a == b
}

func TestServiceValidate(t *testing.T) {
	for _, s := range []Service{{Name: "W3SVC", StartMode: "auto"}, {Name: "a b", State: "stopped"}, {Name: "x", StartMode: "delayed", State: "running"}, {Name: "x", StartMode: "manual"}, {Name: "x", StartMode: "disabled", State: "stopped"}} {
		if err := s.Validate(); err != nil {
			t.Errorf("%+v: %v", s, err)
		}
	}
	for want, s := range map[string]Service{
		"not a service name":        {Name: "a*b", State: "running"},
		"start_mode":                {Name: "x", StartMode: "boot"},
		"state":                     {Name: "x", State: "paused"},
		"set start_mode, state":     {Name: "x"},
		"disabled service can't be": {Name: "x", StartMode: "disabled", State: "running"},
	} {
		if err := s.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want %q", s, err, want)
		}
	}
}

func TestServiceInSync(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		s              Service
		answer         map[string]any
		exists, inSync bool
	}{
		"missing":           {Service{Name: "x", State: "running"}, map[string]any{"exists": false}, false, false},
		"delayed":           {Service{Name: "x", StartMode: "delayed", State: "running"}, map[string]any{"exists": true, "start": "Automatic", "delayed": true, "status": "Running"}, true, true},
		"auto, not delayed": {Service{Name: "x", StartMode: "delayed"}, map[string]any{"exists": true, "start": "Automatic", "status": "Running"}, true, false},
		"stopped":           {Service{Name: "x", State: "running"}, map[string]any{"exists": true, "start": "Manual", "status": "Stopped"}, true, false},
		"mode only":         {Service{Name: "x", StartMode: "disabled"}, map[string]any{"exists": true, "start": "Disabled", "status": "Stopped"}, true, true},
	} {
		exists, inSync, err := ServiceInSync(ctx, &fake{answers: []map[string]any{ok(c.answer)}}, c.s)
		if err != nil || exists != c.exists || inSync != c.inSync {
			t.Errorf("%s: exists %v, in sync %v, %v", name, exists, inSync, err)
		}
	}
	if _, _, err := ServiceInSync(ctx, &fake{answers: []map[string]any{ok("x")}}, Service{Name: "x"}); err == nil || !strings.Contains(err.Error(), "reading service x") {
		t.Errorf("garbled: %v", err)
	}
	if _, _, err := ServiceInSync(ctx, &fake{err: errors.New("down")}, Service{Name: "x"}); err == nil {
		t.Error("runner error ignored")
	}
	f := &fake{answers: []map[string]any{ok(nil)}}
	if err := ApplyService(ctx, f, Service{Name: "x", StartMode: "auto", State: "running"}); err != nil || args(f, 0)["start_mode"] != "auto" || args(f, 0)["state"] != "running" {
		t.Errorf("apply: %v, sent %v", err, f.sent)
	}
}

func TestFeature(t *testing.T) {
	ctx := context.Background()
	if (Feature{Name: "Web-Server"}).Validate() != nil || (Feature{Name: "Web*"}).Validate() == nil || (Feature{Name: "-x"}).Validate() == nil {
		t.Error("feature names")
	}
	for name, c := range map[string]struct {
		f               Feature
		answer          map[string]any
		inSync, pending bool
	}{
		"removed":           {Feature{Name: "x", Absent: true}, map[string]any{"exists": true, "state": "Removed"}, true, false},
		"uninstall pending": {Feature{Name: "x", Absent: true}, map[string]any{"exists": true, "state": "UninstallPending"}, true, true},
		"installed, absent": {Feature{Name: "x", Absent: true}, map[string]any{"exists": true, "state": "Installed", "installed": true}, false, false},
		"install pending":   {Feature{Name: "x"}, map[string]any{"exists": true, "state": "InstallPending"}, true, true},
	} {
		f := &fake{answers: []map[string]any{ok(c.answer)}}
		inSync, pending, err := FeatureInSync(ctx, f, c.f)
		if err != nil || inSync != c.inSync || pending != c.pending {
			t.Errorf("%s: in sync %v, pending %v, %v", name, inSync, pending, err)
		}
	}
	// Removing a feature asks about nothing under it.
	f := &fake{answers: []map[string]any{ok(map[string]any{"exists": true, "state": "Available"})}}
	if _, _, _ = FeatureInSync(ctx, f, Feature{Name: "x", Absent: true, SubFeatures: true, ManagementTools: true}); args(f, 0)["sub_features"] != false || args(f, 0)["management_tools"] != false {
		t.Errorf("sent %v", f.sent[0])
	}
	if _, _, err := FeatureInSync(ctx, &fake{answers: []map[string]any{ok(map[string]any{"exists": false})}}, Feature{Name: "Nope"}); err == nil || err.Error() != "Windows has no feature named Nope here" {
		t.Errorf("missing: %v", err)
	}
	if _, _, err := FeatureInSync(ctx, &fake{answers: []map[string]any{ok(1)}}, Feature{Name: "x"}); err == nil || !strings.Contains(err.Error(), "reading feature x") {
		t.Errorf("garbled: %v", err)
	}
	if _, _, err := FeatureInSync(ctx, &fake{err: errors.New("down")}, Feature{Name: "x"}); err == nil {
		t.Error("runner error ignored")
	}

	f = &fake{answers: []map[string]any{ok(map[string]any{"restart": true})}}
	if restart, err := ApplyFeature(ctx, f, Feature{Name: "x", SubFeatures: true}, time.Minute); err != nil || !restart || args(f, 0)["present"] != true || args(f, 0)["sub_features"] != true {
		t.Errorf("apply: %v, %v, sent %v", restart, err, f.sent)
	}
	if _, err := ApplyFeature(ctx, &fake{answers: []map[string]any{ok("x")}}, Feature{Name: "x"}, time.Minute); err == nil || !strings.Contains(err.Error(), "reading the result for feature x") {
		t.Errorf("garbled: %v", err)
	}
	if _, err := ApplyFeature(ctx, &fake{answers: []map[string]any{{"ok": false, "error": "0x800f0922"}}}, Feature{Name: "x"}, time.Minute); err == nil || err.Error() != "0x800f0922" {
		t.Errorf("host error: %v", err)
	}
}
