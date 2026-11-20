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

func TestOptionalFeature(t *testing.T) {
	ctx := context.Background()
	for _, n := range []string{"TelnetClient", "Microsoft-Windows-Subsystem-Linux", "NetFx3", "WCF-HTTP-Activation45"} {
		if err := (OptionalFeature{Name: n}).Validate(); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	for _, f := range []OptionalFeature{{Name: ""}, {Name: "-x"}, {Name: "Tel*"}, {Name: "a b"}, {Name: "x", Source: "D:\\a\nb"}} {
		if f.Validate() == nil {
			t.Errorf("%+v: no error", f)
		}
	}
	for name, c := range map[string]struct {
		f               OptionalFeature
		state           string
		inSync, pending bool
	}{
		"enabled":                {OptionalFeature{Name: "x"}, "Enabled", true, false},
		"enable pending":         {OptionalFeature{Name: "x"}, "EnablePending", true, true},
		"disabled, want present": {OptionalFeature{Name: "x"}, "Disabled", false, false},
		"payload removed":        {OptionalFeature{Name: "x"}, "DisabledWithPayloadRemoved", false, false},
		"disabled":               {OptionalFeature{Name: "x", Absent: true}, "Disabled", true, false},
		"disable pending":        {OptionalFeature{Name: "x", Absent: true}, "DisablePending", true, true},
		"removed, want absent":   {OptionalFeature{Name: "x", Absent: true}, "DisabledWithPayloadRemoved", true, false},
		"enabled, want absent":   {OptionalFeature{Name: "x", Absent: true}, "Enabled", false, false},
	} {
		f := &fake{answers: []map[string]any{ok(map[string]any{"exists": true, "state": c.state})}}
		inSync, pending, err := OptionalFeatureInSync(ctx, f, c.f)
		if err != nil || inSync != c.inSync || pending != c.pending || args(f, 0)["name"] != "x" {
			t.Errorf("%s: in sync %v, pending %v, %v", name, inSync, pending, err)
		}
	}
	if _, _, err := OptionalFeatureInSync(ctx, &fake{answers: []map[string]any{ok(map[string]any{"exists": false})}}, OptionalFeature{Name: "Nope"}); err == nil || err.Error() != "Windows has no optional feature named Nope here" {
		t.Errorf("unknown: %v", err)
	}
	if _, _, err := OptionalFeatureInSync(ctx, &fake{answers: []map[string]any{ok(1)}}, OptionalFeature{Name: "x"}); err == nil || !strings.Contains(err.Error(), "reading optional feature x") {
		t.Errorf("bad answer: %v", err)
	}
	if _, _, err := OptionalFeatureInSync(ctx, &fake{err: errors.New("down")}, OptionalFeature{Name: "x"}); err == nil {
		t.Error("runner error ignored")
	}

	f := &fake{answers: []map[string]any{ok(map[string]any{"restart": true})}}
	restart, err := ApplyOptionalFeature(ctx, f, OptionalFeature{Name: "x", IncludeParent: true, Source: `D:\sources\sxs`}, time.Minute)
	if err != nil || !restart || args(f, 0)["present"] != true || args(f, 0)["include_parent"] != true || args(f, 0)["source"] != `D:\sources\sxs` {
		t.Errorf("enable: %v %v, sent %v", restart, err, f.sent)
	}
	// Disabling sends no -All: it means nothing to Disable-WindowsOptionalFeature.
	f = &fake{answers: []map[string]any{ok(map[string]any{"restart": false})}}
	if restart, err := ApplyOptionalFeature(ctx, f, OptionalFeature{Name: "x", Absent: true, IncludeParent: true}, time.Minute); err != nil || restart || args(f, 0)["present"] != false || args(f, 0)["include_parent"] != false {
		t.Errorf("disable: %v %v, sent %v", restart, err, f.sent)
	}
}
