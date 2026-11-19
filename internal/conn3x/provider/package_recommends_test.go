// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"
)

// install_recommends only says how a package would be installed, so
// changing it alone keeps the revision, and handlers don't fire.
func TestPackageInstallRecommendsKeepsRevision(t *testing.T) {
	vals := packageSchema().Block.EmptyValue().AsValueMap()
	vals["name"], vals["revision"] = cty.StringVal("nginx"), cty.StringVal("abc")
	prior := cty.ObjectVal(vals)
	vals["install_recommends"] = cty.False
	if got := planRevision(prior, cty.ObjectVal(vals)).GetAttr("revision"); !got.RawEquals(cty.StringVal("abc")) {
		t.Fatalf("revision after toggling install_recommends: %#v", got)
	}
	vals["version"] = cty.StringVal("1.26")
	if got := planRevision(prior, cty.ObjectVal(vals)).GetAttr("revision"); got.IsKnown() {
		t.Fatalf("a version change kept the revision: %#v", got)
	}
}
