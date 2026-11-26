// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestPackageRepoReleaseValidate(t *testing.T) {
	crb := cty.ListVal([]cty.Value{cty.StringVal("crb")})
	for want, attrs := range map[string]map[string]cty.Value{
		`repository ID "epel*" is not valid`: {"enable_repositories": cty.ListVal([]cty.Value{cty.StringVal("epel*")})},
		`target_release "a b" is not valid`:  {"target_release": cty.StringVal("a b")},
		"sets one or the other":              {"enable_repositories": crb, "target_release": cty.StringVal("trixie-backports")},
	} {
		attrs["name"] = cty.StringVal("nasm")
		diags := validatePackage(packageObj(t, attrs))
		if !diags.HasErrors() || !strings.Contains(diags.Err().Error(), want) {
			t.Errorf("%v: %v, want %q", attrs, diags.Err(), want)
		}
	}
	for _, attrs := range []map[string]cty.Value{
		{"enable_repositories": crb},
		{"enable_repositories": cty.ListVal([]cty.Value{cty.UnknownVal(cty.String)})},
		{"target_release": cty.StringVal("trixie-backports")},
		{"target_release": cty.UnknownVal(cty.String)},
	} {
		attrs["name"] = cty.StringVal("nasm")
		if diags := validatePackage(packageObj(t, attrs)); diags.HasErrors() {
			t.Errorf("%v refused: %v", attrs, diags.Err())
		}
	}
}

// Other repositories or another release offer another newest version, so
// a change to either doesn't plan the one the refresh read.
func TestPackageRepoReleasePlan(t *testing.T) {
	prior := packageObj(t, map[string]cty.Value{
		"id": cty.StringVal("203.0.113.10:package:nasm"), "name": cty.StringVal("nasm"), "state": cty.StringVal("latest"),
		"on_remove": cty.StringVal("forget"), "installed_version": cty.StringVal("0:2.16-1"), "latest_version": cty.StringVal("0:2.16-1"),
	})
	same := packageObj(t, map[string]cty.Value{"name": cty.StringVal("nasm"), "state": cty.StringVal("latest")})
	if p := planPkg(t, prior, same); !p.RawEquals(prior) {
		t.Fatalf("unchanged: %#v", p)
	}
	for name, attr := range map[string]map[string]cty.Value{
		"repositories": {"enable_repositories": cty.ListVal([]cty.Value{cty.StringVal("crb")})},
		"release":      {"target_release": cty.StringVal("trixie-backports")},
	} {
		attr["name"], attr["state"] = cty.StringVal("nasm"), cty.StringVal("latest")
		if p := planPkg(t, prior, packageObj(t, attr)); p.GetAttr("latest_version").IsKnown() {
			t.Errorf("new %s planned a known latest_version: %#v", name, p)
		}
	}
}
