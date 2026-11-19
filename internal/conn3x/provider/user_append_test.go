// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/modules/account"
)

// With append, state records only the listed groups the user is in.
func TestUserStateAppend(t *testing.T) {
	base := func(appendGroups cty.Value) cty.Value {
		vals := userSchema().Block.EmptyValue().AsValueMap()
		vals["name"], vals["append"] = cty.StringVal("a"), appendGroups
		vals["groups"] = cty.SetVal([]cty.Value{cty.StringVal("docker"), cty.StringVal("video")})
		return cty.ObjectVal(vals)
	}
	u := account.User{Exists: true, Groups: []string{"audio", "docker"}}
	if got := userState(base(cty.True), u).GetAttr("groups"); !got.RawEquals(cty.SetVal([]cty.Value{cty.StringVal("docker")})) {
		t.Errorf("append: %#v", got)
	}
	if got := userState(base(cty.NullVal(cty.Bool)), u).GetAttr("groups"); !got.RawEquals(cty.SetVal([]cty.Value{cty.StringVal("audio"), cty.StringVal("docker")})) {
		t.Errorf("complete list: %#v", got)
	}
}
