// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package differ

import (
	"testing"

	"github.com/opentofu/opentofu/internal/command/jsonformat/structured"
	"github.com/opentofu/opentofu/internal/command/jsonformat/structured/attribute_path"
	"github.com/opentofu/opentofu/internal/command/jsonprovider"
)

func TestConn3xUngated(t *testing.T) {
	step := &jsonprovider.Block{Attributes: map[string]*jsonprovider.Attribute{
		"only_if": {WriteOnly: true},
		"skipped": {Computed: true},
	}}
	for name, c := range map[string]struct {
		values structured.ChangeMap
		hide   bool
	}{
		"no only_if":       {structured.ChangeMap{After: map[string]interface{}{}}, true},
		"pending":          {structured.ChangeMap{After: map[string]interface{}{}, Unknown: map[string]interface{}{"skipped": true}}, false},
		"skipped":          {structured.ChangeMap{After: map[string]interface{}{"skipped": true}}, false},
		"was skipped, ran": {structured.ChangeMap{Before: map[string]interface{}{"skipped": true}, After: map[string]interface{}{}}, false},
	} {
		c.values.ReplacePaths, c.values.RelevantAttributes = attribute_path.Empty(false), attribute_path.AlwaysMatcher()
		if got := conn3xUngated(step, c.values); got != c.hide {
			t.Errorf("%s: hidden = %v, want %v", name, got, c.hide)
		}
	}
	other := &jsonprovider.Block{Attributes: map[string]*jsonprovider.Attribute{"only_if": {WriteOnly: true}}}
	if conn3xUngated(other, structured.ChangeMap{}) {
		t.Error("only_if hidden on a resource without skipped")
	}
}
