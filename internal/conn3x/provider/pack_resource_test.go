// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func TestPackValidate(t *testing.T) {
	paths, d := cty.ListVal([]cty.Value{cty.StringVal("/var/log/app")}), cty.StringVal("/backup/app.tgz")
	for name, attrs := range map[string]map[string]cty.Value{
		"relative":    {"paths": cty.ListVal([]cty.Value{cty.StringVal("var/log")}), "dest": d},
		"null path":   {"paths": cty.ListVal([]cty.Value{cty.NullVal(cty.String)}), "dest": d},
		"no paths":    {"paths": cty.ListValEmpty(cty.String), "dest": d},
		"format":      {"paths": paths, "dest": d, "format": cty.StringVal("rar")},
		"mode":        {"paths": paths, "dest": d, "mode": cty.StringVal("644")},
		"on_remove":   {"paths": paths, "dest": d, "on_remove": cty.StringVal("purge")},
		"rel exclude": {"paths": paths, "dest": d, "exclude": cty.ListVal([]cty.Value{cty.StringVal("*.gz")})},
	} {
		if diags := validatePack(objFor(packSchema(), attrs)); !diags.HasErrors() {
			t.Errorf("%s: no error", name)
		}
	}
	ok := map[string]cty.Value{"paths": paths, "dest": d, "format": cty.StringVal("zip"), "exclude": cty.ListVal([]cty.Value{cty.StringVal("/var/log/app/*.gz")}), "mode": cty.StringVal("0640")}
	if diags := validatePack(objFor(packSchema(), ok)); diags.HasErrors() {
		t.Error(diags.Err())
	}
}

// The archive is in sync while it's there and its files hash as they did
// when it was packed. Out of sync plans a change with the hash unknown, so
// apply can fill it in.
func TestPackSync(t *testing.T) {
	cfg := objFor(packSchema(), map[string]cty.Value{"paths": cty.ListVal([]cty.Value{cty.StringVal("/srv/data")}), "dest": cty.StringVal("/srv/a.tgz")})
	vals := cfg.AsValueMap()
	vals["id"], vals["on_remove"], vals["sources_sha256"] = cty.StringVal("x"), cty.StringVal("forget"), cty.StringVal("abc")
	state := cty.ObjectVal(vals)

	for _, c := range []struct {
		sum     string
		present bool
		want    bool
	}{
		{"abc", true, true},
		{"def", true, false},
		{"abc", false, false},
	} {
		got := packSynced(state, c.sum, c.present)
		if got.GetAttr("in_sync").True() != c.want {
			t.Errorf("%s %v: in_sync %v", c.sum, c.present, got.GetAttr("in_sync"))
		}
		if got.GetAttr("sources_sha256").AsString() != "abc" {
			t.Errorf("refresh changed sources_sha256: %v", got.GetAttr("sources_sha256"))
		}
		plan := planPack(providers.PlanResourceChangeRequest{PriorState: got, ProposedNewState: got})
		if p := plan.PlannedState; p.GetAttr("sources_sha256").IsKnown() == !c.want || p.GetAttr("in_sync").IsKnown() == !c.want {
			t.Errorf("%s %v: planned %#v", c.sum, c.present, p)
		}
	}
	vals["sources_sha256"] = cty.NullVal(cty.String)
	if packSynced(cty.ObjectVal(vals), "abc", true).GetAttr("in_sync").True() {
		t.Error("no packed hash is in sync")
	}
}
